"""Flask control plane for AI code reviews.

REST surface (the v1 subset the platform roadmap calls for — create, status,
report, list, cancel, with review_id acting as the idempotency key
[07-api-specification, 04-low-level-design]):

    GET    /api/v1/health                     liveness + provider reachability
    GET    /api/v1/config                     effective config, secrets removed
    GET    /api/v1/providers                  configured cloud + on-prem LLMs
    GET    /api/v1/models                     models a provider/endpoint offers
    GET    /api/v1/personas                   named reviewer personas
    POST   /api/v1/reviews                    start a review (or dry_run a prompt)
    GET    /api/v1/reviews                    list reviews
    GET    /api/v1/reviews/<id>               progress / status
    GET    /api/v1/reviews/<id>/prompt        the consolidated prompt
    POST   /api/v1/reviews/<id>/restart       resume a failed/cancelled review
    POST   /api/v1/reviews/<id>/pause         stop now, resumable any time later
    POST   /api/v1/reviews/<id>/resume        continue a paused/interrupted review
    POST   /api/v1/reviews/<id>/cancel        stop after the current unit
    GET    /api/v1/reviews/<id>/report        the finished report
    GET    /api/v1/reports                    all reports + resumable checkpoints
    GET    /api/v1/reports/<name>             one report, straight off disk
    DELETE /api/v1/reports/<name>             delete one report and its sidecars
    GET    /                                  service descriptor (JSON)
    GET    /healthz                           liveness  - no auth, for probes
    GET    /readyz                            readiness - no auth, for probes

This is an API and nothing else. The test console that used to be served at
`/` is its own service now (`frontend/`, image `review-console`), which
reverse-proxies /api/ to this one - so the backend ships no HTML, no static
files and no browser-facing surface of its own.

Reports outlive job records (the registry is in-memory), so the /reports
routes read the directory rather than the registry: they keep answering
after a restart, which is when a client needs them most.

SECURITY POSTURE (be honest about it): there is no user authentication here.
Optionally require a shared secret in `X-API-Key`, and bind to 127.0.0.1 by
default. Real identity (OIDC + per-repository authorization) is platform
work [05-security-authorization-design]; do not expose this to a network
without at least the API key and TLS in front of it.
"""

from __future__ import annotations

import collections
import datetime
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

from code_review_mcp import llm
from code_review_mcp.config import settings
from code_review_mcp.findings import FindingsError, load_findings_file
from code_review_mcp.pipeline import _resolve_output
from code_review_mcp.repo_ingest import IngestError, check_access

from .config import (ApiConfig, ConfigError, EndpointError, check_endpoint_allowed,
                     is_loopback_host,
                     load_config, load_dotenv, normalize_endpoint)
from . import review_state
from .llm_presets import (PRESETS, PresetError, models_headers, parse_llm,
                          public_presets)
from .jobs import ACTIVE
from .k8s_jobs import STALE_PROGRESS_SECONDS, create_store
from .prompts import build_prompt

VALID_MODES = ("quick", "brief", "deep")

# A commit a caller may pin a review to: the full SHA only (see the
# engine's clone_repo for why).
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# Reachable without X-API-Key. None of them reveals any configuration.
_UNAUTHENTICATED = frozenset({"/", "/healthz", "/readyz"})


def _problem(status: int, title: str, detail: str, **extra) -> tuple[Any, int]:
    """RFC 9457-style problem response, as the API spec prescribes."""
    body = {"type": "about:blank", "title": title, "status": status,
            "detail": detail, **extra}
    return jsonify(body), status


def _sanitize_id(raw: str) -> str:
    """Review ids name files, so keep them filesystem-safe."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", (raw or "").strip()).strip(".")


def _read_json(path: Path) -> dict[str, Any] | None:
    """A JSON object from disk, or None if it is missing or unreadable.

    None-on-failure on purpose: every caller here treats these files as
    optional progress artifacts. A half-written or hand-edited one should
    degrade the view, not 500 the request.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _fit_file_time(points: list[tuple[int, float]]) -> tuple[float, float] | None:
    """Fit seconds = overhead + per_char * size to measured files.

    Not seconds-per-character alone: the first version did that, and on a
    live run it predicted 69 minutes for a review that took 5. Most of a
    file's time is the model thinking and writing - closer to a fixed cost
    per file than to anything proportional to size - so a few small files
    finishing first made "seconds per character" huge, which was then
    multiplied by every large file left.

    So the size term is only kept when the measurements actually show
    larger files taking longer. Otherwise this is a plain per-file average,
    which is what the evidence supports. Never a negative overhead or a
    negative cost per character.
    """
    if not points:
        return None
    n = len(points)
    mean_t = sum(t for _, t in points) / n
    mean_s = sum(s for s, _ in points) / n
    spread = sum((s - mean_s) ** 2 for s, _ in points)
    if n < 2 or spread == 0:
        return mean_t, 0.0
    per_char = sum((s - mean_s) * (t - mean_t) for s, t in points) / spread
    if per_char <= 0:
        return mean_t, 0.0  # bigger files are not measurably slower
    overhead = mean_t - per_char * mean_s
    if overhead < 0:
        return 0.0, mean_t / mean_s if mean_s else 0.0
    return overhead, per_char


def _file_timing(job, sizes: dict[str, int], pending: list[str],
                 current: str | None) -> tuple[dict[str, Any] | None, int | None]:
    """(running-file timing, seconds left for the whole review), or Nones.

    Learned only from files that finished during THIS run, each with its
    own measured duration. A resumed review is therefore not credited with
    checkpoint files that took no time here, which would otherwise pull
    every estimate towards zero.

    With REVIEW_PARALLEL > 1 the per-file durations are still exact, and the
    total is divided by the number of files in flight at once. Files that
    FAILED in this run never produce a duration, so they do not feed the fit.

    `expected_seconds` for the running file is a guess: how long a model
    thinks about a file is not knowable in advance. The UI shows it as an
    estimate and never as complete.
    """
    if job is None or job.status != "reviewing":
        return None, None
    fit = _fit_file_time([(sizes.get(p, 0), t) for p, t in job.durations])
    predict = (lambda size: fit[0] + fit[1] * size) if fit else None

    now = time.monotonic()
    running = None
    left_on_current = 0.0
    if current and job.current_file_started is not None:
        elapsed = max(0.0, now - job.current_file_started)
        expected = predict(sizes.get(current, 0)) if predict else None
        running = {"path": current, "elapsed_seconds": int(elapsed),
                   "expected_seconds": (int(round(expected))
                                        if expected is not None else None)}
        if expected is not None:
            left_on_current = max(0.0, expected - elapsed)

    if predict is None:
        return running, None  # nothing finished yet in this run to learn from
    in_flight = max(1, settings.parallel)
    eta = (sum(predict(sizes.get(p, 0)) for p in pending) / in_flight
           + left_on_current)
    return running, int(round(eta))


def _scanner_status(review_id: str) -> dict[str, Any] | None:
    """How each deterministic scanner fared, from `<id>.findings.json`.

    None when there is no findings file: the scanner tier did not run for
    this review (not installed, disabled, or findings were supplied from
    outside). That is reported as-is rather than as "no findings", because
    those are different facts and only one of them is reassuring.
    """
    scan = _read_json(_resolve_output(f"{review_id}.findings.json"))
    if not scan:
        return None
    return {"run": list(scan.get("scanners_run") or []),
            "failed": dict(scan.get("scanners_failed") or {}),
            "coverage": dict(scan.get("coverage") or {})}


# Files that live beside a report and describe a review, but are not one.
# The plan carries `repo_url`, so without this it was listed as a report
# whenever a review was running. `.error.json` and `.progress.json` are
# the worker sidecars agreed in docs/WORK-TRACKER.md, excluded ahead of
# time so they cannot appear as reports when they land.
_SIDECARS = (".partial.json", ".plan.json", ".error.json",
             ".progress.json", review_state.PAUSED_SUFFIX)


def _truthy(value: str | None) -> bool:
    """Query-string booleans, as a human would write them."""
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _int_arg(name: str, default: int, maximum: int) -> int:
    """A bounded integer query parameter that tolerates junk.

    `?limit=abc` is a client mistake, not a server fault: fall back to the
    default rather than raising a 500 out of int().
    """
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


def create_app(config_path: str | None = None,
               cfg: ApiConfig | None = None) -> Flask:
    cfg = cfg or load_config(config_path)
    # Reports, checkpoints and findings files are shared with the MCP server.
    settings.output_dir = str(Path(cfg.output_dir).resolve())
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    # static_folder=None: Flask otherwise registers a /static route by
    # default, and a pure API has no business serving files.
    app = Flask(__name__, static_folder=None)
    app.config["API_CONFIG"] = cfg
    # local (default): in-process JobStore. kubernetes: real Jobs, see
    # k8s_jobs.py and docs/job-container-contract.md. Selected by
    # REVIEW_API_EXECUTION_MODE, not by config/api.yaml — see create_store.
    store = create_store(cfg)
    app.config["JOB_STORE"] = store

    # ---------------- cross-cutting ----------------

    @app.after_request
    def _cors(response):
        """Allow the demo UI to call this API from another origin."""
        origin = request.headers.get("Origin", "")
        allowed = cfg.cors_origins
        if origin and ("*" in allowed or origin in allowed):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        elif "*" in allowed:
            response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = \
            "Content-Type, X-API-Key"
        response.headers["Access-Control-Allow-Methods"] = \
            "GET, POST, DELETE, OPTIONS"
        return response

    @app.before_request
    def _auth():
        if request.method == "OPTIONS":
            return ("", 204)
        if not cfg.api_key:
            return None
        # Probes must work whether or not a key is set: a kubelet sends no
        # X-API-Key, and a liveness probe answered with 401 restarts a
        # perfectly healthy pod forever.
        if request.path in _UNAUTHENTICATED:
            return None
        if request.headers.get("X-API-Key", "") != cfg.api_key:
            return _problem(401, "Unauthorized",
                            "A valid X-API-Key header is required.")
        return None

    # ---------------- discovery ----------------

    @app.get("/api/v1/health")
    def health():
        """Liveness plus, optionally, a real probe of a provider endpoint."""
        payload: dict[str, Any] = {
            "status": "ok",
            "providers_configured": len(cfg.providers),
            "default_provider": cfg.default_provider,
            "active_review": None,
        }
        active = store.active()
        if active:
            payload["active_review"] = {"job_id": active.job_id,
                                        "review_id": active.review_id,
                                        "status": active.status}
        if request.args.get("probe") in ("1", "true", "yes"):
            name = request.args.get("provider") or cfg.default_provider
            # ?endpoint=100.x.y.z lets the console test an address BEFORE a
            # review is started against it, which is the difference between
            # "it failed" and "it failed for this reason".
            payload["probe"] = _probe_provider(
                name, request.args.get("endpoint") or request.args.get("base_url"))
        return jsonify(payload)

    def _resolve_endpoint(raw: str | None) -> str:
        """Validate a caller-supplied endpoint, or '' when none was given."""
        if not raw or not raw.strip():
            return ""
        if not cfg.allow_custom_endpoint:
            raise EndpointError(
                "This server does not accept a custom endpoint "
                "(allow_custom_endpoint is false). Choose a configured "
                f"provider: {', '.join(sorted(cfg.providers))}.")
        base_url = normalize_endpoint(raw)
        check_endpoint_allowed(base_url, cfg.custom_endpoint_networks)
        return base_url

    def _llm_from_body(raw: Any) -> dict[str, str] | None:
        """The site's AI service choice (sent by the gateway), resolved to
        an address this server will call. None when the request has none,
        which keeps the configured providers in charge as before.

        Raises PresetError / EndpointError with a sentence for the user."""
        # The key may come in the X-LLM-Key header instead of the body, the
        # same way the clone token rides X-Repo-Token: headers stay out of
        # anything that logs request payloads.
        header_key = request.headers.get("X-LLM-Key", "").strip()
        if header_key and isinstance(raw, dict):
            raw = {**raw, "api_key": header_key}
        llm_choice = parse_llm(raw)
        if llm_choice is None:
            return None
        preset = PRESETS[llm_choice["preset"]]
        base_url = preset.base_url or _resolve_endpoint(llm_choice["endpoint"])
        return {**llm_choice, "base_url": base_url}

    def _list_models(base_url: str, api_key: str) -> list[str]:
        saved = (settings.lm_base_url, settings.lm_api_key)
        try:
            settings.lm_base_url, settings.lm_api_key = base_url, api_key
            client = llm.make_client()
            headers = models_headers(base_url, api_key)
            if headers:
                client = client.with_options(default_headers=headers)
            return sorted(m.id for m in client.models.list().data)
        finally:
            settings.lm_base_url, settings.lm_api_key = saved

    @app.get("/api/v1/llm/presets")
    def get_llm_presets():
        """The AI services Settings offers, with fixed addresses shown."""
        try:
            default = cfg.provider(None)
            server_default = {"provider": default.name,
                              "base_url": default.base_url,
                              "model": default.default_model or None}
        except ConfigError:
            server_default = None
        return jsonify({"presets": public_presets(),
                        "server_default": server_default})

    @app.post("/api/v1/llm/models")
    def post_llm_models():
        """Test an AI service choice and list its models.

        POST, not GET, because the body carries an API key, and a query
        string ends up in access logs. The key is used for this one call and
        then forgotten. An unreachable service is a 200 with reachable:
        false, like GET /api/v1/models, so Settings can show the reason.
        """
        body = request.get_json(silent=True) or {}
        try:
            choice = _llm_from_body(body.get("llm"))
        except (PresetError, EndpointError) as exc:
            return _problem(400, "Bad Request", str(exc))
        if choice is None:
            return _problem(400, "Bad Request", "Send an llm object to test.")
        try:
            default = cfg.provider(None)
        except ConfigError as exc:
            if not choice["base_url"]:
                return _problem(400, "Bad Request", str(exc))
            default = None
        base_url = choice["base_url"] or default.base_url
        # A local server that wants no key still needs SOME string for the
        # client; the server's own default key covers its own address.
        api_key = choice["api_key"] or (
            default.api_key if default and not choice["base_url"]
            else "not-needed")
        try:
            models = _list_models(base_url, api_key)
        except Exception as exc:  # noqa: BLE001 - any failure is the answer
            text = str(exc)
            if choice["api_key"]:
                text = text.replace(choice["api_key"], "[key]")
            return jsonify({"reachable": False, "base_url": base_url,
                            "error": text[:300]})
        return jsonify({"reachable": True, "base_url": base_url,
                        "models": models, "model_count": len(models)})

    def _fetch_models(name: str, endpoint: str | None = None,
                      limit: int | None = None) -> dict[str, Any]:
        """List the models an endpoint offers — the model picker's source.

        Doubles as the reachability probe: an endpoint that can enumerate its
        models is demonstrably up, reachable, and (for cloud) authenticated.
        """
        try:
            provider = cfg.provider(name)
        except ConfigError as exc:
            return {"provider": name, "reachable": False, "error": str(exc)}
        # Report the provider actually used, not the (possibly absent) one
        # asked for — a caller that omitted it should still learn the default.
        name = provider.name
        try:
            override = _resolve_endpoint(endpoint)
        except EndpointError as exc:
            return {"provider": name, "reachable": False, "error": str(exc),
                    "endpoint": endpoint,
                    "hint": "Enter an address such as 100.83.14.22, "
                            "100.83.14.22:1234, or http://host:1234/v1."}
        saved = (settings.lm_base_url, settings.lm_api_key)
        try:
            settings.lm_base_url = override or provider.base_url
            settings.lm_api_key = provider.api_key
            models = sorted(m.id for m in llm.make_client().models.list().data)
            return {"provider": name, "location": provider.location,
                    "reachable": True,
                    "models": models[:limit] if limit else models,
                    "model_count": len(models),
                    "default_model": provider.default_model or None,
                    "base_url": settings.lm_base_url,
                    "endpoint_override": override or None}
        except Exception as exc:  # noqa: BLE001 - report any connectivity issue
            # A provider's own setup_hint beats the generic advice: for a
            # remote on-prem endpoint the generic text just restates the URL
            # that timed out.
            hint = provider.setup_hint or (
                "For on-prem: is the server running at "
                f"{provider.base_url}? For cloud: is "
                f"{provider.api_key_env or 'the API key'} set?")
            return {"provider": name, "location": provider.location,
                    "reachable": False, "error": str(exc)[:300],
                    "models": [], "model_count": 0,
                    "default_model": provider.default_model or None,
                    "base_url": override or provider.base_url,
                    "endpoint_override": override or None, "hint": hint}
        finally:
            settings.lm_base_url, settings.lm_api_key = saved

    def _probe_provider(name: str, endpoint: str | None = None) -> dict[str, Any]:
        """Reachability probe: the model list, trimmed for a health payload."""
        return _fetch_models(name, endpoint, limit=25)

    @app.get("/api/v1/models")
    def get_models():
        """Models available from a provider (or a caller-supplied endpoint).

        This is what fills the model dropdown, so it returns the FULL list
        rather than the health probe's trimmed preview — a cloud provider can
        offer dozens.

        An endpoint that is simply down is not a client error: the response is
        200 with `reachable: false` plus a hint, so a picker can degrade to
        "type an id" instead of showing a failure.
        """
        result = _fetch_models(request.args.get("provider"),
                               request.args.get("endpoint")
                               or request.args.get("base_url"))
        return jsonify(result)

    @app.get("/api/v1/config")
    def get_config():
        return jsonify(cfg.public())

    @app.get("/api/v1/providers")
    def get_providers():
        return jsonify({
            "default": cfg.default_provider,
            "providers": [p.public() for p in cfg.providers.values()],
        })

    @app.get("/api/v1/personas")
    def get_personas():
        return jsonify({
            "default": cfg.default_persona,
            "personas": [{"name": n, "prompt": p}
                         for n, p in sorted(cfg.personas.items())],
        })

    @app.get("/api/v1/repo-access")
    def repo_access():
        """Can we clone this repo? Accepts an optional per-request token."""
        repo_url = request.args.get("repo_url", "")
        token = request.headers.get("X-Repo-Token", "")
        if not repo_url:
            return _problem(400, "Bad Request", "repo_url is required.")
        try:
            return jsonify(check_access(repo_url,
                                        request.args.get("branch") or None,
                                        token=token or None))
        except IngestError as exc:
            return _problem(400, "Bad Request", str(exc))

    # ---------------- reviews ----------------

    @app.post("/api/v1/reviews")
    def create_review():
        """Consolidate the request, build the prompt, and start the review.

        Requirement 1: review_id, repo_url, access_token (private repos),
        review type, deterministic findings file, plus branch/files/
        extensions/provider/model/persona/focus.
        Requirement 2: the assembled prompt comes back in the response; with
        dry_run=true it is built and returned WITHOUT calling the model.
        """
        body = request.get_json(silent=True) or {}

        review_id = _sanitize_id(body.get("review_id", ""))
        if not review_id:
            return _problem(400, "Bad Request",
                            "review_id is required (it names the report and "
                            "is the idempotency key for restarts).")
        repo_url = (body.get("repo_url") or "").strip()
        if not repo_url:
            return _problem(400, "Bad Request", "repo_url is required.")
        mode = (body.get("mode") or cfg.default_mode).strip().lower()
        if mode not in VALID_MODES:
            return _problem(400, "Bad Request",
                            f"mode must be one of {', '.join(VALID_MODES)}.")

        # The credential is read from the body (or an X-Repo-Token header) and
        # from here on only ever travels to the clone. It is never logged,
        # stored, or echoed back.
        access_token = (body.get("access_token")
                        or request.headers.get("X-Repo-Token", "") or "").strip()

        try:
            provider = cfg.provider(body.get("provider"))
            persona_name, persona_prompt = cfg.persona_prompt(
                body.get("persona")) if not body.get("system_prompt") \
                else ("(inline)", "")
        except ConfigError as exc:
            return _problem(400, "Bad Request", str(exc))

        # Optional per-review endpoint: "run this against the model at
        # 100.83.14.22". Validated here so a bad address fails the request
        # instead of the review, ten minutes in.
        try:
            endpoint = _resolve_endpoint(body.get("endpoint")
                                         or body.get("base_url"))
        except EndpointError as exc:
            return _problem(400, "Bad Request", str(exc),
                            hint="Give an address like 100.83.14.22, "
                                 "100.83.14.22:1234, or http://host:1234/v1. "
                                 "Test it first with "
                                 "GET /api/v1/health?probe=1&endpoint=…")

        # Deterministic findings (the scanner hand-off): validate NOW so a bad
        # filename fails the request instead of the review.
        findings_file = (body.get("findings_file") or "").strip()
        findings_summary: dict[str, Any] | None = None
        if findings_file:
            try:
                _, meta = load_findings_file(_resolve_output(findings_file))
                findings_summary = meta
            except FindingsError as exc:
                return _problem(400, "Bad Request", str(exc))

        commit = (body.get("commit") or "").strip().lower()
        if commit and not _COMMIT_RE.match(commit):
            return _problem(400, "Bad Request",
                            "commit must be a full 40-character SHA.")

        # The site-wide AI service from Settings, when the gateway sends
        # one. It overrides the provider's address, model and key for this
        # review only; the key goes to the run and is never stored.
        try:
            llm_choice = _llm_from_body(body.get("llm"))
        except PresetError as exc:
            return _problem(400, "Bad Request", str(exc))
        except EndpointError as exc:
            return _problem(400, "Bad Request", str(exc))
        if llm_choice:
            endpoint = llm_choice["base_url"] or endpoint

        files = body.get("files") or None
        prompt_info = build_prompt(
            mode=mode, repo_url=repo_url, review_id=review_id,
            persona_name=persona_name, persona_prompt=persona_prompt,
            system_prompt=body.get("system_prompt", ""),
            focus=body.get("focus"), findings_summary=findings_summary,
            branch=body.get("branch", ""), files=files,
        )

        if body.get("dry_run"):
            # Requirement 2, literal reading: consolidate and hand the prompt
            # back without spending a token.
            return jsonify({
                "status": "dry_run",
                "review_id": review_id,
                "provider": provider.name,
                "endpoint": endpoint or provider.base_url,
                "endpoint_override": endpoint or None,
                "model": body.get("model") or provider.default_model or None,
                "prompt": prompt_info,
                "note": "Nothing was sent to the model. Repeat without "
                        "dry_run to run this review.",
            })

        existing = store.get(review_id)
        if existing and existing.status in ACTIVE:
            return jsonify({
                **existing.public(),
                "action": "already_running",
                "hint": "This review_id is already in progress; poll it "
                        "instead of starting a duplicate.",
            }), 409
        active = store.active()
        if active:
            return jsonify({
                # `action` is the HTTP outcome and is present on BOTH 409s,
                # so a client can tell them apart with one field instead of
                # inferring it from which keys happen to be missing.
                #
                # `review_id` is deliberately still absent here: a consumer
                # currently distinguishes busy from already_running by its
                # absence, and adding it before that consumer moves to
                # `action` would break them. Add it once they have.
                "action": "busy",
                "status": "busy",
                "active": active.public(),
                "hint": "One review runs at a time (a single local model "
                        "would only queue against itself). Retry when the "
                        "active review finishes.",
            }), 409

        # Starting this review_id again supersedes an earlier pause of it.
        review_state.clear_paused(settings.output_dir, review_id)
        job = store.create(
            review_id=review_id, repo_url=repo_url, mode=mode,
            provider=provider.name,
            model=((llm_choice or {}).get("model") or body.get("model")
                   or provider.default_model or ""),
            system_prompt=prompt_info["system_prompt"],
            prompt_info=prompt_info, branch=body.get("branch", ""),
            files=files, findings_file=findings_file,
            extensions=body.get("extensions"), access_token=access_token,
            base_url=endpoint, commit=commit,
            llm_preset=(llm_choice or {}).get("preset", ""),
            llm_api_key=(llm_choice or {}).get("api_key", ""),
        )
        # `status` always carries the REVIEW's lifecycle state (identical to
        # what polling returns); the HTTP outcome lives in `action`. Mixing
        # the two made this field race with the worker thread.
        return jsonify({**job.public(), "action": "accepted",
                        "prompt": prompt_info,
                        "poll": f"/api/v1/reviews/{job.review_id}"}), 202

    @app.get("/api/v1/reviews")
    def list_reviews():
        status = request.args.get("status")
        limit = min(int(request.args.get("limit", 50)), 200)
        return jsonify({"reviews": [j.public()
                                    for j in store.list(status, limit)]})

    @app.get("/api/v1/reviews/<review>")
    def get_review(review: str):
        """Requirement 3: progress of a review.

        Falls back to the reports volume when the registry has never heard
        of the review (review-api restarted since): a finished, paused or
        interrupted review is still described truthfully, with
        `"source": "disk"`, instead of a bare 404.
        """
        job = store.get(review)
        if not job:
            disk = _disk_status(review)
            if disk:
                return jsonify(disk)
            return _problem(
                404, "Not Found", f"No review {review!r} in this server's "
                "memory.", resumable_checkpoints=_checkpoints(),
                hint="If the API restarted, the job registry was lost but "
                     "checkpoints survive: POST /api/v1/reviews with the same "
                     "review_id to resume, or check /api/v1/reports.")
        return jsonify(job.public())

    @app.get("/api/v1/reviews/<review>/prompt")
    def get_review_prompt(review: str):
        job = store.get(review)
        if not job:
            return _problem(404, "Not Found", f"No review {review!r}.")
        return jsonify({"review_id": job.review_id, "prompt": job.prompt})

    @app.get("/api/v1/reviews/<review>/files")
    def get_review_files(review: str):
        """Per-file progress: what is done, failed, running, still pending.

        Deliberately returns file PATHS and STATE only — never file contents,
        and never issue text. A progress view needs to know that `a/b.py`
        finished with 2 issues; it does not need the issues themselves, and
        this endpoint is polled far more often than the report is read.

        Three sources, in order of preference, so the view keeps working
        across a review's whole life:
          - `<id>.plan.json`  — every file the review set out to cover.
          - `<id>.partial.json` — units finished/failed so far (live).
          - `<id>.json`       — the finished report, once the first two are
                                cleaned up on completion.
        Works from disk alone, so it still answers after an API restart has
        emptied the in-memory job registry (the same reason
        /api/v1/reports exists). What does NOT survive a restart, or reach
        this process at all in kubernetes mode, is the live timing: the
        running file and both time estimates come back null then, and the
        file states still show.

        Also reports how each deterministic scanner fared on this review
        (`scanners`), because a scanner that failed silently otherwise just
        looks like a review with no scanner findings.
        """
        rid = _sanitize_id(review)
        job = store.get(review)
        plan = _read_json(_resolve_output(f"{rid}.plan.json"))
        ckpt = _read_json(_resolve_output(f"{rid}.partial.json"))
        # The finished report answers "what is done" once the checkpoint is
        # gone. Not while this id is running again, though: until the new
        # run writes its first checkpoint, the report on disk is the PREVIOUS
        # run's, and would show files done that this run has not touched.
        running_now = bool(job and job.status in ACTIVE)
        report = None if (ckpt or running_now) else _read_json(
            _resolve_output(f"{rid}.json"))
        if not (plan or ckpt or report):
            return _problem(
                404, "Not Found",
                f"No per-file progress for {review!r}.",
                hint="A review writes its plan once cloning and file "
                     "selection finish; before that there is nothing to "
                     "list. Finished reviews are covered by "
                     f"/api/v1/reports/{rid}.")

        finished = (ckpt or report or {}).get("reviews") or []
        done = {r.get("file"): r for r in finished if isinstance(r, dict)}
        failed = {f.get("file"): f
                  for f in ((ckpt or report or {}).get("failures") or [])
                  if isinstance(f, dict)}

        # Ordered file list: the plan when we have it, otherwise whatever the
        # checkpoint/report happens to name (a review interrupted before the
        # plan was written still shows its completed units rather than 404).
        if plan:
            entries = [(f.get("path"), f.get("language"), f.get("size"),
                        f.get("lines"))
                       for f in plan.get("files") or []
                       if isinstance(f, dict) and f.get("path")]
        else:
            entries = [(p, None, None, None) for p in [*done, *failed] if p]

        # The file in flight is tracked by the job store from the engine's
        # "<path>: reviewing" announcement (see jobs._ACTIVE_FILE). It still
        # has to be a path the plan lists and not already finished: anything
        # else marks nothing as running — never a guessed file.
        current = None
        if job and job.status == "reviewing" and job.current_file:
            known = {e[0] for e in entries}
            if job.current_file in known and job.current_file not in done \
                    and job.current_file not in failed:
                current = job.current_file

        # What did NOT fully check the files, so that "no findings" is only
        # ever claimed about a file every applicable check actually covered.
        scanners = _scanner_status(rid)
        if scanners is None:
            review_gaps = ["no scanner results were recorded"]
            partly_parsed: set[str] = set()
        else:
            review_gaps = [f"{name} failed" for name in sorted(scanners["failed"])]
            semgrep = scanners["coverage"].get("semgrep") or {}
            partly_parsed = set(semgrep.get("error_files") or [])
            if semgrep.get("error_files_truncated"):
                # Some errored files went unnamed, so any file may be one.
                review_gaps.append("semgrep errors not all listed")

        files = []
        for path, language, size, lines in entries:
            if path in done:
                # Deterministic findings live beside the model's, under their
                # own key, so counting `issues` alone reported a file with
                # three Gitleaks secrets as "1 finding". Counted per scanner,
                # still as numbers only.
                statics = done[path].get("static_findings") or []
                by_scanner = collections.Counter(
                    str(f.get("source") or "scanner")
                    for f in statics if isinstance(f, dict))
                entry = {"state": "done",
                         "issues": len(done[path].get("issues") or []),
                         "scanner_findings": dict(by_scanner),
                         "score": done[path].get("score"),
                         "scan_gaps": review_gaps + (
                             ["semgrep could only partly parse it"]
                             if path in partly_parsed else [])}
            elif path in failed:
                # The error string names the failure mode ("model returned no
                # JSON", a connection drop) — operational detail about OUR
                # pipeline, not repository content.
                entry = {"state": "failed", "error": failed[path].get("error")}
            elif path == current:
                entry = {"state": "in_progress"}
            else:
                entry = {"state": "pending"}
            files.append({"path": path, "language": language, "size": size,
                          "lines": lines, **entry})

        sizes = {f["path"]: f["size"] for f in files if f["size"]}
        pending = [f["path"] for f in files if f["state"] == "pending"]
        running, eta = _file_timing(job, sizes, pending, current)

        counts = collections.Counter(f["state"] for f in files)
        return jsonify({
            "review_id": rid,
            "mode": (plan or ckpt or report or {}).get("mode")
                    or (job.mode if job else None),
            "commit": (plan or ckpt or report or {}).get("commit"),
            "status": (job.status if job
                       else (_disk_status(rid) or {}).get("status", "unknown")),
            "source": ("plan" if plan else "checkpoint" if ckpt else "report"),
            "counts": {"total": len(files),
                       "done": counts.get("done", 0),
                       "failed": counts.get("failed", 0),
                       "in_progress": counts.get("in_progress", 0),
                       "pending": counts.get("pending", 0)},
            "current": running,
            "eta_seconds": eta,
            # How many measured files the estimates rest on, so the page can
            # say how far to trust them: "from 2 files" is a rough guess, "from
            # 40" much less so. Null when there is no live timing at all.
            "estimate_based_on": (len(job.durations)
                                  if job and job.status == "reviewing" else None),
            "scanners": scanners,
            "files": files,
        })

    def _disk_status(review: str) -> dict[str, Any] | None:
        return review_state.disk_status(
            settings.output_dir, _sanitize_id(review),
            stale_seconds=STALE_PROGRESS_SECONDS)

    @app.post("/api/v1/reviews/<review>/pause")
    def pause_review(review: str):
        """Stop a running review so it can be resumed later - days later.

        Kubernetes mode stops at once (the Job is deleted; the checkpoint
        already holds every finished unit). Local mode stops after the unit
        in flight, with `pausing: true` until then. Either way the pause is
        recorded on the reports volume, so it survives a restart of this
        service. Idempotent: pausing a paused review is a 200.
        """
        job = store.get(review)
        if not job:
            disk = _disk_status(review)
            if disk and disk["status"] == "paused":
                return jsonify({**disk, "action": "already_paused"})
            if disk and disk.get("detached"):
                return _problem(
                    409, "Conflict",
                    "This review runs in a Job this server no longer tracks "
                    "(review-api restarted while it ran), so it cannot be "
                    "paused from here. It still finishes on its own.")
            return _problem(404, "Not Found", f"No running review {review!r}.")
        if job.status == "paused":
            return jsonify({**job.public(), "action": "already_paused"})
        if not store.pause(job):
            return _problem(409, "Conflict",
                            f"Review is {job.status}; nothing to pause.",
                            status_of_review=job.status)
        return jsonify({**job.public(),
                        "action": "paused" if job.status == "paused"
                        else "pausing"}), 202

    @app.post("/api/v1/reviews/<review>/resume")
    def resume_review(review: str):
        """Continue a paused, failed or interrupted review from its checkpoint.

        Works without the in-memory registry: everything a resume needs is
        read from the reports volume - the checkpoint (repo, commit, mode,
        prompt), the pause marker (branch, model, provider) - with the
        request body as the fallback for a review stopped before either was
        written. The run is pinned to the checkpoint's COMMIT, because the
        checkpoint is only reused when the commit matches, and the branch
        may have moved on while the review was paused.

        A fresh token comes with the request (X-Repo-Token), like when
        starting: the one the review began with is long gone.
        """
        rid = _sanitize_id(review)
        if not rid:
            return _problem(400, "Bad Request", "A review id is required.")
        job = store.get(rid)
        if job and job.status in ACTIVE:
            return _problem(409, "Conflict",
                            f"Review {rid!r} is already {job.status}.",
                            status_of_review=job.status)
        if job is None:
            disk = _disk_status(rid)
            if disk and disk.get("detached"):
                return _problem(409, "Conflict",
                                "This review is still running in a Job this "
                                "server no longer tracks; wait for it.")
            if disk and disk["status"] == "completed":
                return _problem(409, "Conflict",
                                f"Review {rid!r} already finished.")
        elif job.status == "completed":
            return _problem(409, "Conflict", f"Review {rid!r} already finished.")

        body = request.get_json(silent=True) or {}
        out = settings.output_dir
        ckpt = review_state.read_checkpoint(out, rid) or {}
        marker = review_state.read_paused(out, rid) or {}
        plan = _read_json(_resolve_output(f"{rid}.plan.json")) or {}
        known = job.public() if job else {}

        def first(*values: Any) -> str:
            return next((str(v).strip() for v in values if v), "")

        # Repository, commit and mode come from the checkpoint first: they
        # are exactly what it is matched against, so anything else would
        # only make it be ignored.
        repo_url = first(ckpt.get("repo_url"), marker.get("repo_url"),
                         plan.get("repo_url"), known.get("repo_url"),
                         body.get("repo_url"))
        mode = first(ckpt.get("mode"), marker.get("mode"), plan.get("mode"),
                     known.get("mode"), body.get("mode")).lower() \
            or cfg.default_mode
        commit = first(ckpt.get("commit"), marker.get("commit"),
                       plan.get("commit"), known.get("commit"),
                       body.get("commit")).lower()
        branch = first(marker.get("branch"), known.get("branch"),
                       body.get("branch"))
        if not repo_url:
            return _problem(404, "Not Found",
                            f"Nothing to resume for {rid!r}: no checkpoint, "
                            "no pause record, and no repo_url in the request.")
        if mode not in VALID_MODES:
            return _problem(400, "Bad Request", f"Unknown mode {mode!r}.")
        if commit and not _COMMIT_RE.match(commit):
            # An "unknown" from a failed rev-parse, or a bad request value:
            # resume on the branch tip rather than refuse.
            commit = ""
        try:
            provider = cfg.provider(first(body.get("provider"),
                                          marker.get("provider"),
                                          known.get("provider")) or None)
        except ConfigError as exc:
            return _problem(400, "Bad Request", str(exc))
        try:
            llm_choice = _llm_from_body(body.get("llm"))
        except (PresetError, EndpointError) as exc:
            return _problem(400, "Bad Request", str(exc))
        model = first((llm_choice or {}).get("model"), body.get("model"),
                      marker.get("model"), known.get("model"),
                      provider.default_model)

        system_prompt = first(ckpt.get("system_prompt"),
                              ((job.prompt if job else None) or {})
                              .get("system_prompt"))
        if not system_prompt:
            persona_name, persona_prompt = cfg.persona_prompt(None)
            system_prompt = build_prompt(
                mode=mode, repo_url=repo_url, review_id=rid,
                persona_name=persona_name,
                persona_prompt=persona_prompt)["system_prompt"]

        active = store.active()
        if active:
            return jsonify({
                "action": "busy", "status": "busy",
                "active": active.public(),
                "hint": "One review runs at a time. Resume this one when "
                        "the active review finishes.",
            }), 409

        token = (body.get("access_token")
                 or request.headers.get("X-Repo-Token", "") or "").strip()
        review_state.clear_paused(out, rid)
        new_job = store.create(
            review_id=rid, repo_url=repo_url, mode=mode,
            provider=provider.name, model=model,
            system_prompt=system_prompt,
            prompt_info={"system_prompt": system_prompt, "resumed": True},
            branch=branch, access_token=token,
            base_url=((llm_choice or {}).get("base_url")
                      or (job.base_url if job else "")),
            commit=commit,
            llm_preset=(llm_choice or {}).get("preset", ""),
            llm_api_key=(llm_choice or {}).get("api_key", ""))
        restored = (review_state.checkpoint_units(ckpt)
                    if ckpt.get("mode") == mode else 0)
        return jsonify({
            **new_job.public(), "action": "resumed",
            "restored_units": restored, "pinned_commit": commit or None,
            "note": ("Reusing the checkpoint; only the remaining units are "
                     "reviewed." if restored else
                     "No checkpoint to reuse: the review starts over."),
        }), 202

    @app.post("/api/v1/reviews/<review>/restart")
    def restart_review(review: str):
        """Requirement 4: restart after a failure — resumes from checkpoint.

        Only the in-process store can re-run a job record in place. Anywhere
        else (kubernetes mode, or a review this process has forgotten) this
        is the same as /resume - it used to be a 500 there.
        """
        job = store.get(review)
        if not job or not hasattr(store, "restart"):
            return resume_review(review)
        if job.status in ACTIVE:
            return _problem(409, "Conflict",
                            "This review is still running; cancel it first.")
        body = request.get_json(silent=True) or {}
        token = (body.get("access_token")
                 or request.headers.get("X-Repo-Token", "") or "").strip()
        prompt_info = job.prompt or {}
        store.restart(job, system_prompt=prompt_info.get("system_prompt", ""),
                      access_token=token, extensions=body.get("extensions"))
        return jsonify({
            **job.public(), "action": "restarted",
            "note": "Completed units recorded in the checkpoint are reused; "
                    "only the remaining ones are reviewed. Watch "
                    "restored_units in the status.",
        }), 202

    @app.post("/api/v1/reviews/<review>/retry-failed")
    def retry_failed_files(review: str):
        """Re-review only the files that failed, merged into the SAME report.

        Distinct from restart: restart RESUMES a run that failed, this tops
        up a run that COMPLETED with gaps. A deep run typically ends with a
        share of files carrying "Model failed to return valid JSON" — a
        response-format problem that says nothing about the code, and on a
        measured run was spread evenly across file sizes rather than
        clustered at the large end, which is the profile a second attempt
        recovers.

        Reads the report from DISK, so it still works after a restart has
        emptied the in-memory job registry.
        """
        target = _report_file(review)
        if target is None:
            return _problem(400, "Bad Request",
                            f"Not a usable review id: {review!r}.")
        if not target.is_file():
            return _problem(404, "Not Found",
                            f"No report for {review!r} to retry.",
                            hint="Run the review first; retry-failed tops up "
                                 "a finished report.")
        job = store.get(review)
        if job and job.status in ACTIVE:
            return _problem(409, "Conflict",
                            f"Review {review!r} is {job.status}; wait for it "
                            "to finish.", status_of_review=job.status)
        if store.active():
            return jsonify({
                "action": "busy", "status": "busy",
                "active": store.active().public(),
                "hint": "One review runs at a time. Retry when it finishes.",
            }), 409

        report = json.loads(target.read_text(encoding="utf-8"))
        failed = [f.get("file") for f in report.get("failures", [])]
        if not failed:
            # Idempotent: nothing to do is a success, not an error.
            return jsonify({
                "review_id": review, "action": "nothing_to_retry",
                "failures": 0,
                "stats": report.get("stats"),
                "note": "This report has no failed files.",
            })

        body = request.get_json(silent=True) or {}
        token = (body.get("access_token")
                 or request.headers.get("X-Repo-Token", "") or "").strip()
        try:
            provider = cfg.provider(body.get("provider"))
        except ConfigError as exc:
            return _problem(400, "Bad Request", str(exc))
        prompt_info = (job.prompt if job else None) or {}
        system_prompt = (body.get("system_prompt")
                         or prompt_info.get("system_prompt") or "")
        if not system_prompt:
            # The registry lost this run's prompt (an API restart), so
            # rebuild the default one rather than refusing the retry.
            persona_name, persona_prompt = cfg.persona_prompt(None)
            system_prompt = build_prompt(
                mode=report.get("mode", "deep"),
                repo_url=report.get("repo_url", ""),
                review_id=review,
                persona_name=persona_name,
                persona_prompt=persona_prompt,
            )["system_prompt"]

        new_job = store.retry_failed(
            review_id=review, system_prompt=system_prompt,
            provider=provider.name,
            model=(body.get("model") or provider.default_model or ""),
            access_token=token, report=report)
        return jsonify({
            **new_job.public(), "action": "retrying",
            "files_to_retry": len(failed),
            "note": "Only the failed files are re-reviewed; successes are "
                    "merged into the existing report and removed from "
                    "failures. Running this twice cannot duplicate entries.",
        }), 202

    @app.post("/api/v1/reviews/<review>/cancel")
    def cancel_review(review: str):
        job = store.get(review)
        if not job:
            return _problem(404, "Not Found", f"No review {review!r}.")
        if not store.cancel(job):
            return _problem(409, "Conflict",
                            f"Review is {job.status}; nothing to cancel.")
        return jsonify({**job.public(), "action": "cancelling",
                        "note": "Stops after the unit in flight so the "
                                "checkpoint stays complete and restartable."})

    def _report_file(name: str) -> Path | None:
        """Resolve a report NAME to a file inside the reports directory.

        This is the containment boundary for the by-name routes: the name
        arrives from the URL, so it is reduced to a filesystem-safe stem
        and the resolved path is re-checked against the reports directory.
        Returns None for anything that cannot be a report there.
        """
        base = Path(settings.output_dir or ".").resolve()
        stem = _sanitize_id(name)
        if stem.endswith(".json"):
            stem = stem[: -len(".json")]
        if not stem:
            return None
        target = (base / f"{stem}.json").resolve()
        # Belt and braces: sanitising already removed separators, so a path
        # that still escapes the directory is not one we will touch.
        if target.parent != base:
            return None
        return target

    def _report_view(target: Path):
        """Render a report file per ?view= and ?file=.

        Shared by the review-scoped route and the by-name route so both
        speak exactly the same shapes.
        """
        data = json.loads(target.read_text(encoding="utf-8"))
        view = request.args.get("view", "summary")
        if view == "full":
            return jsonify(data)
        if view == "markdown":
            md = target.with_suffix(".md")
            return app.response_class(
                md.read_text(encoding="utf-8") if md.is_file() else "",
                mimetype="text/markdown")
        wanted = request.args.get("file")
        if wanted:
            for entry in data.get("reviews", []):
                if entry.get("file") == wanted:
                    return jsonify(entry)
            return _problem(404, "Not Found",
                            f"No review for file {wanted!r} in this report.")
        return jsonify({
            "report": target.name,
            "repo_url": data.get("repo_url"),
            "commit": data.get("commit"),
            "model": data.get("model"),
            "mode": data.get("mode"),
            "generated_at": data.get("generated_at"),
            "authenticated_clone": data.get("authenticated"),
            "resumed": data.get("resumed", False),
            "stats": data.get("stats"),
            "overall": data.get("overall"),
            "deterministic": data.get("deterministic"),
            # What the review did NOT read, so a summary can never imply
            # coverage the run did not have.
            "excluded": data.get("excluded"),
            "files": [{"file": r.get("file"), "score": r.get("score"),
                       "issues": len(r.get("issues", []))
                       + len(r.get("static_findings", []))}
                      for r in data.get("reviews", [])],
            "failures": data.get("failures", []),
        })

    @app.get("/api/v1/reviews/<review>/report")
    def get_review_report(review: str):
        """The finished report: summary (default), one file, or the full JSON."""
        job = store.get(review)
        target = (Path(job.report_path) if job and job.report_path
                  else _resolve_output(f"{_sanitize_id(review)}.json"))
        if not target.is_file():
            return _problem(404, "Not Found",
                            f"No report for {review!r} yet.",
                            status_of_review=(job.status if job else "unknown"))
        return _report_view(target)

    def _report_meta(path: Path) -> dict[str, Any]:
        """Headline facts about one report on disk.

        Never raises: a half-written or hand-edited report must still show
        up in the listing, marked `readable: false`, rather than 500 the
        whole endpoint for every other report beside it.
        """
        stat = path.stat()
        meta: dict[str, Any] = {
            "name": path.name,
            "review_id": path.stem,
            "size_bytes": stat.st_size,
            "modified_at": datetime.datetime.fromtimestamp(
                stat.st_mtime, datetime.timezone.utc)
            .isoformat(timespec="seconds").replace("+00:00", "Z"),
            "has_markdown": path.with_suffix(".md").is_file(),
            "links": {"self": f"/api/v1/reports/{path.stem}",
                      "markdown": f"/api/v1/reports/{path.stem}?view=markdown",
                      "full": f"/api/v1/reports/{path.stem}?view=full"},
        }
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {**meta, "readable": False}
        if not isinstance(data, dict):
            return {**meta, "readable": False}
        stats = data.get("stats") or {}
        return {
            **meta, "readable": True,
            # The reports directory also holds findings inputs and other JSON.
            # Flag them rather than hiding them: a client can filter, and a
            # file nobody expected stays visible instead of vanishing.
            "is_report": bool(data.get("repo_url") or stats),
            "repo_url": data.get("repo_url"), "branch": data.get("branch"),
            "commit": data.get("commit"), "mode": data.get("mode"),
            "model": data.get("model"),
            "generated_at": data.get("generated_at"),
            "files_reviewed": stats.get("files_reviewed"),
            "files_excluded": stats.get("files_excluded"),
            "issues_total": stats.get("issues_total"),
            "issues_by_severity": stats.get("issues_by_severity"),
            "score": (data.get("overall") or {}).get(
                "score", stats.get("average_score")),
        }

    @app.get("/api/v1/reports")
    def list_reports():
        """Every report on disk, newest first, with its headline facts.

        Reports outlive job records (those are in-memory), so this is the
        endpoint that still answers "what reviews do we have?" after a
        restart.
        """
        base = Path(settings.output_dir or ".")
        limit = _int_arg("limit", 200, 1000)
        reports = []
        if base.is_dir():
            for f in sorted(base.glob("*.json"),
                            key=lambda p: p.stat().st_mtime, reverse=True):
                if f.name.endswith(_SIDECARS):
                    continue
                reports.append(_report_meta(f))
                if len(reports) >= limit:
                    break
        return jsonify({"reports_dir": str(base), "count": len(reports),
                        "reports": reports,
                        "resumable_checkpoints": _checkpoints()})

    @app.get("/api/v1/reports/<name>")
    def get_report(name: str):
        """One report by NAME, straight off disk.

        The review-scoped route needs a job this process started; this one
        does not, which is what a client wants after an API restart.
        Same `?view=summary|full|markdown` and `?file=` as that route.
        """
        target = _report_file(name)
        if target is None:
            return _problem(400, "Bad Request",
                            f"Not a usable report name: {name!r}.")
        if not target.is_file():
            return _problem(404, "Not Found", f"No report {target.name!r}.",
                            hint="GET /api/v1/reports lists what is on disk.")
        return _report_view(target)

    # Everything a review leaves on the reports volume, by suffix. Deleting
    # a review removes exactly these, never a glob: another review's id can
    # start with this one's.
    _REVIEW_FILES = (".json", ".md", ".notes.md", ".plan.json",
                     ".partial.json", ".progress.json", ".error.json",
                     review_state.PAUSED_SUFFIX, ".findings.json")

    @app.delete("/api/v1/reviews/<review>")
    def delete_review(review: str):
        """Delete a review completely: report, checkpoint, scan results,
        pause record and progress files. IRREVERSIBLE, and so refused while
        the review is running (pause it first; a paused review has no Job).

        Unlike DELETE /api/v1/reports/<name>, the checkpoint goes too: the
        person asked for the review to be gone, not just its report.
        """
        rid = _sanitize_id(review)
        if not rid or rid != review:
            return _problem(400, "Bad Request", f"Not a review id: {review!r}.")
        job = store.get(rid)
        if job and job.status in ACTIVE:
            return _problem(409, "Conflict",
                            f"Review {rid!r} is {job.status}. Pause it, then "
                            "delete it.", status_of_review=job.status)
        out = Path(settings.output_dir)
        live = review_state.read_progress(out, rid)
        updated = (live or {}).get("updated_at")
        if (not job and isinstance(updated, (int, float))
                and time.time() - updated < STALE_PROGRESS_SECONDS):
            # A Job this process no longer tracks is still writing.
            return _problem(409, "Conflict",
                            f"Review {rid!r} is still running in a job this "
                            "server no longer tracks. Delete it when it ends.")
        removed = []
        for suffix in _REVIEW_FILES:
            path = out / f"{rid}{suffix}"
            try:
                if path.is_file():
                    path.unlink()
                    removed.append(path.name)
            except OSError as exc:
                return _problem(500, "Internal Server Error",
                                f"Could not delete {path.name}: {exc.strerror}",
                                removed=removed)
        forgotten = store.forget(rid)
        if not removed and not job:
            return _problem(404, "Not Found", f"No review {rid!r}.")
        return jsonify({"action": "deleted", "review_id": rid,
                        "removed": removed, "forgotten": forgotten})

    @app.delete("/api/v1/reports/<name>")
    def delete_report(name: str):
        """Delete one report and its sidecars. IRREVERSIBLE.

        Only ever the artifacts belonging to this report name — the `.json`,
        its `.md` render, its `.notes.md` and its `.plan.json` — and only
        inside the reports
        directory. The resume checkpoint is KEPT unless
        `?include_checkpoint=true`, because deleting it also destroys the
        ability to resume an interrupted review, which is a bigger loss
        than a report that can be regenerated.
        """
        target = _report_file(name)
        if target is None:
            return _problem(400, "Bad Request",
                            f"Not a usable report name: {name!r}.")
        review_id = target.stem
        job = store.get(review_id)
        if job and job.status in ACTIVE:
            return _problem(
                409, "Conflict",
                f"Review {review_id!r} is {job.status}; its report is still "
                "being written.", status_of_review=job.status,
                hint=f"POST /api/v1/reviews/{review_id}/cancel first, "
                     "then delete.")
        if not target.is_file():
            return _problem(404, "Not Found", f"No report {target.name!r}.",
                            hint="GET /api/v1/reports lists what is on disk.")

        checkpoint = target.with_name(f"{review_id}.partial.json")
        drop = [target, target.with_suffix(".md"),
                target.with_suffix(".notes.md"),
                # Kept after a review finishes for its sizes; meaningless
                # without the report, so it goes when the report does.
                target.with_suffix(".plan.json"),
                # The worker's sidecars (contract v2): a failure reason and
                # live timing mean nothing once their report is gone.
                target.with_suffix(".error.json"),
                target.with_suffix(".progress.json")]
        if _truthy(request.args.get("include_checkpoint")):
            drop.append(checkpoint)

        deleted: list[str] = []
        failed: list[dict[str, str]] = []
        for path in drop:
            try:
                if path.is_file():
                    path.unlink()
                    deleted.append(path.name)
            except OSError as exc:
                failed.append({"file": path.name, "error": str(exc)})
        if failed:
            # Partial deletion is worth reporting precisely: on Windows a
            # file open in another process cannot be unlinked, and silently
            # claiming success would leave the caller with a phantom report.
            return _problem(500, "Internal Server Error",
                            f"Deleted {len(deleted)} file(s); "
                            f"{len(failed)} could not be removed.",
                            deleted=deleted, failed=failed)

        body: dict[str, Any] = {"action": "deleted", "review_id": review_id,
                                "deleted": deleted}
        if checkpoint.is_file():
            body["checkpoint_kept"] = checkpoint.name
            body["note"] = ("A resume checkpoint remains, so this review is "
                            "still restartable. Pass "
                            "?include_checkpoint=true to remove it too.")
        return jsonify(body)

    def _checkpoints() -> list[dict[str, Any]]:
        """Interrupted reviews that a restart would resume."""
        base = Path(settings.output_dir or ".")
        found = []
        if base.is_dir():
            for p in sorted(base.glob("*.partial.json")):
                try:
                    ck = json.loads(p.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                found.append({
                    "review_id": p.name.replace(".partial.json", ""),
                    "repo_url": ck.get("repo_url"), "mode": ck.get("mode"),
                    "done": ck.get("progress", {}).get("done"),
                    "total": ck.get("progress", {}).get("total"),
                    "updated_at": ck.get("updated_at"),
                })
        return found

    # ---------------- service surface (no UI) ----------------

    @app.get("/")
    def service_descriptor():
        """What this is, for anyone who lands here with a browser.

        Deliberately not a page: the console is a separate service. Minimal
        and unauthenticated - it names no provider, path or setting.
        """
        return jsonify({
            "service": "review-api",
            "kind": "api",
            "api": "/api/v1",
            "health": "/healthz",
            "ready": "/readyz",
            "note": "This service has no user interface. The test console is "
                    "a separate service (review-console) that proxies /api/ "
                    "to this one.",
        })

    @app.get("/healthz")
    def healthz():
        """Liveness: the process is up and answering.

        Checks nothing external, on purpose. If this depended on the model
        or on GitHub, an LLM outage would make Kubernetes restart a healthy
        API in a loop - and lose every in-memory job record each time.
        """
        return jsonify({"status": "ok"})

    @app.get("/readyz")
    def readyz():
        """Readiness: able to do its job right now.

        Two hard dependencies, both local:
        - a writable reports directory, or no review can be saved and no
          report listed;
        - a usable temp directory, or no repository can be cloned. With a
          read-only root filesystem and no volume on /tmp, every review
          failed with "No usable temporary directory found" while this
          endpoint still said ready.
        The model is NOT a readiness condition: with it down the API can
        still list, read and delete reports, and /api/v1/health?probe=1 is
        where model reachability is reported.
        """
        out = Path(settings.output_dir or ".")
        if not (out.is_dir() and os.access(out, os.W_OK)):
            return jsonify({"status": "not_ready",
                            "reason": "reports directory is not writable"}), 503
        try:
            scratch = tempfile.gettempdir()
        except FileNotFoundError:
            scratch = None
        if not scratch or not os.access(scratch, os.W_OK):
            return jsonify({"status": "not_ready",
                            "reason": "no writable temp directory for clones "
                                      "(mount a volume on /tmp)"}), 503
        return jsonify({"status": "ready"})

    return app


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="AI review API (Flask)")
    parser.add_argument("--config", default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--env-file", default=None,
                        help="Defaults to the repository's .env if present.")
    args = parser.parse_args()

    # One file configures a workstation. Compose reads .env on its own; a
    # direct launch needs this. Must happen BEFORE the config is parsed,
    # because the config file interpolates ${VAR} from the environment.
    env_file = load_dotenv(args.env_file)

    cfg = load_config(args.config)
    app = create_app(cfg=cfg)
    host = args.host or cfg.host
    port = args.port or cfg.port
    if env_file:
        print(f"[review-api] env:    {env_file}")
    print(f"[review-api] config: {cfg.config_path}")
    print(f"[review-api] reports: {settings.output_dir}")
    print(f"[review-api] providers: {', '.join(cfg.providers)} "
          f"(default: {cfg.default_provider})")
    print(f"[review-api] auth: "
          f"{'X-API-Key required' if cfg.api_key else 'OPEN (no API key)'}")

    # Say plainly whether other machines can reach this, and refuse to let
    # "shared with the team" quietly become "unauthenticated and writable".
    reachable = not is_loopback_host(host)
    print(f"[review-api] bind: {host}:{port} — "
          + ("this machine only" if not reachable
             else "REACHABLE FROM THE NETWORK"))
    if reachable and not cfg.api_key:
        print("\n"
              "  ! " + "=" * 68 + "\n"
              "  ! This API is reachable from other machines and has NO API "
              "KEY.\n"
              "  ! Anyone who can reach it can start reviews on your GPU, read\n"
              "  ! every report, and DELETE them.\n"
              "  !\n"
              "  ! Set REVIEW_API_KEY in .env and restart, then give teammates\n"
              "  ! that value for the console's X-API-Key box.\n"
              "  ! " + "=" * 68 + "\n")
    print(f"[review-api] probes: http://{host}:{port}/healthz  /readyz")
    print("[review-api] no UI here - the test console is the separate "
          "review-console service (frontend/)")
    app.run(host=host, port=port, debug=cfg.debug, threaded=True)


if __name__ == "__main__":
    main()
