"""Tests for the Flask review API.

Covers the six requirements — intake, prompt consolidation, progress,
restart-after-failure, private-repo token routing, configuration — plus the
security property that matters most here: an `access_token` supplied in a
request must never appear in any response, job record, report, or log.
"""

import json
import logging
import re
import time
from pathlib import Path

import pytest

from code_review_mcp import pipeline
from code_review_mcp.config import settings
from code_review_mcp.llm import LLMUnavailableError
from review_api.config import (ApiConfig, ConfigError, EndpointError, Provider,
                               check_endpoint_allowed, load_config,
                               normalize_endpoint)
from review_api.prompts import build_prompt
from test_dummy_repo import dummy_manifest

flask = pytest.importorskip("flask")

TOKEN = "ghp_apiFAKEtoken1234567890abcdefghijklmn"


# ---------------- fixtures ----------------

def _cfg(tmp_path) -> ApiConfig:
    cfg = ApiConfig(
        output_dir=str(tmp_path),
        default_provider="onprem",
        default_mode="brief",
        default_persona="security",
        personas={"security": "You are an application security auditor.",
                  "general": "You are a senior engineer."},
    )
    cfg.providers = {
        "onprem": Provider(name="onprem", base_url="http://localhost:1234/v1",
                           default_model="local-model", location="on_prem"),
        "cloud": Provider(name="cloud", base_url="https://api.example.com/v1",
                          api_key_env="EXAMPLE_API_KEY",
                          default_model="cloud-model", location="cloud"),
    }
    return cfg


@pytest.fixture
def client(tmp_path, monkeypatch):
    """App wired to a fake review pipeline (no clone, no LLM)."""
    from review_api.app import create_app

    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())

    def fake_review(manifest, prompt, progress=None, mode="brief", **_):
        if progress:
            progress(1, 1, "done")
        return {"repo_url": manifest["repo_url"], "commit": "f1x7ure0",
                "model": "local-model", "generated_at": "now", "mode": mode,
                "stats": {"files_reviewed": len(manifest["files"]),
                          "files_failed": 0, "files_skipped": 0,
                          "issues_total": 0,
                          "issues_by_severity": {}, "average_score": 8},
                "overall": {"summary": "Fine.", "score": 8, "key_issues": []},
                "reviews": [{"file": f["path"], "summary": "ok", "score": 8,
                             "issues": []} for f in manifest["files"]],
                "failures": [], "skipped": []}

    monkeypatch.setattr(pipeline, "review_manifest", fake_review)
    app = create_app(cfg=_cfg(tmp_path))
    app.config.update(TESTING=True)
    return app.test_client()


def _wait(client, review_id, want=("completed", "failed", "cancelled"),
          timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/v1/reviews/{review_id}").get_json()
        if body.get("status") in want:
            return body
        time.sleep(0.05)
    raise AssertionError(f"review {review_id} never reached {want}: {body}")


# ---------------- requirement 6: configuration ----------------

def test_config_file_yaml_round_trip(tmp_path):
    (tmp_path / "api.yaml").write_text(
        "host: 0.0.0.0\nport: 9100\ndefault_mode: deep\n"
        "providers:\n"
        "  local:\n"
        "    base_url: http://localhost:1234/v1\n"
        "    default_model: m1\n"
        "  remote:\n"
        "    base_url: https://api.example.com/v1\n"
        "    api_key_env: EXAMPLE_KEY\n"
        "    location: cloud\n"
        "personas:\n  sec: Be a security auditor.\n",
        encoding="utf-8")
    cfg = load_config(str(tmp_path / "api.yaml"))
    assert cfg.port == 9100 and cfg.default_mode == "deep"
    assert set(cfg.providers) == {"local", "remote"}
    assert cfg.default_provider == "local"          # first entry wins
    assert cfg.providers["remote"].location == "cloud"
    assert cfg.persona_prompt("sec")[1].startswith("Be a security")


def test_config_env_overrides_file(tmp_path, monkeypatch):
    (tmp_path / "api.json").write_text(json.dumps(
        {"port": 8000, "providers": {"p": {"base_url": "http://x/v1"}}}),
        encoding="utf-8")
    monkeypatch.setenv("REVIEW_API_PORT", "9999")
    monkeypatch.setenv("REVIEW_API_DEFAULT_MODE", "quick")
    cfg = load_config(str(tmp_path / "api.json"))
    assert cfg.port == 9999 and cfg.default_mode == "quick"


def test_config_rejects_unknown_keys_and_providers(tmp_path):
    (tmp_path / "bad.json").write_text('{"nope": 1}', encoding="utf-8")
    with pytest.raises(ConfigError, match="Unknown configuration key"):
        load_config(str(tmp_path / "bad.json"))
    (tmp_path / "bad2.json").write_text(
        '{"providers": {"p": {"default_model": "m"}}}', encoding="utf-8")
    with pytest.raises(ConfigError, match="missing 'base_url'"):
        load_config(str(tmp_path / "bad2.json"))


def test_provider_api_key_comes_from_env_not_config(monkeypatch):
    p = Provider(name="c", base_url="https://x/v1", api_key_env="MY_KEY")
    assert p.key_present is False
    monkeypatch.setenv("MY_KEY", "sk-secret")
    assert p.api_key == "sk-secret" and p.key_present is True
    assert "sk-secret" not in json.dumps(p.public())   # never exposed


# ---------------- portability: one config file, many workstations ----------

def test_config_expands_environment_variables(tmp_path, monkeypatch):
    """The committed file must not need editing on a teammate's machine.

    ${VAR:-fallback} keeps the default working with nothing set, while a
    single environment variable moves the endpoint — which is exactly what
    the container needs (LM Studio lives on the host, not in the container).
    """
    (tmp_path / "api.yaml").write_text(
        "port: ${REVIEW_API_PORT:-8000}\n"
        "providers:\n"
        "  lmstudio:\n"
        "    base_url: ${LMSTUDIO_BASE_URL:-http://localhost:1234/v1}\n",
        encoding="utf-8")

    cfg = load_config(str(tmp_path / "api.yaml"))
    assert cfg.providers["lmstudio"].base_url == "http://localhost:1234/v1"
    # Expansion yields a string; the declared type must survive it.
    assert cfg.port == 8000 and isinstance(cfg.port, int)

    monkeypatch.setenv("LMSTUDIO_BASE_URL", "http://host.docker.internal:1234/v1")
    cfg = load_config(str(tmp_path / "api.yaml"))
    assert cfg.providers["lmstudio"].base_url == \
        "http://host.docker.internal:1234/v1"


def test_unset_variable_without_fallback_fails_at_startup(tmp_path):
    """Better a clear startup error than a mangled URL discovered mid-review."""
    (tmp_path / "api.yaml").write_text(
        "providers:\n  p:\n    base_url: ${DEFINITELY_NOT_SET_XYZ}/v1\n",
        encoding="utf-8")
    with pytest.raises(ConfigError, match="DEFINITELY_NOT_SET_XYZ"):
        load_config(str(tmp_path / "api.yaml"))


def test_relative_paths_resolve_against_the_config_file(tmp_path):
    """Not against the cwd — otherwise reports land wherever you launched."""
    cfg_dir = tmp_path / "backend" / "config"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "api.yaml").write_text(
        "output_dir: ../../reports\n"
        "providers:\n  p:\n    base_url: http://x/v1\n", encoding="utf-8")
    cfg = load_config(str(cfg_dir / "api.yaml"))
    assert Path(cfg.output_dir) == (tmp_path / "reports")


def test_shipped_example_config_loads_and_offers_a_cloud_path():
    """The example config is what a teammate copies, so it must be valid.

    It also has to contain a working CLOUD provider: teammates without the
    GPU workstation depend on that entry existing and taking its key from
    the environment rather than from the committed file.
    """
    example = Path(__file__).resolve().parents[1] / "config" / "api.example.yaml"
    cfg = load_config(str(example))

    cloud = [p for p in cfg.providers.values() if p.location == "cloud"]
    assert cloud, "no cloud provider configured"
    assert all(p.api_key_env for p in cloud), "a cloud key must come from env"

    google = cfg.providers["google_ai_studio"]
    assert google.location == "cloud"
    assert google.api_key_env == "GOOGLE_API_KEY"
    assert "generativelanguage.googleapis.com" in google.base_url
    # No secret may be sitting in a file that gets committed.
    assert "sk-" not in example.read_text(encoding="utf-8")


def test_tailscale_provider_takes_one_address_from_the_environment(monkeypatch):
    """A teammate should change exactly one line to use the shared GPU.

    The whole point of this provider is that the base URL is assembled from a
    single value the teammate pastes in, so it must not require editing the
    committed config file.
    """
    example = Path(__file__).resolve().parents[1] / "config" / "api.example.yaml"

    monkeypatch.setenv("TAILSCALE_LMSTUDIO_HOST", "100.83.14.22")
    p = load_config(str(example)).providers["lmstudio_tailscale"]
    assert p.base_url == "http://100.83.14.22:1234/v1"
    assert p.location == "on_prem"          # code stays on machines we own
    assert not p.api_key_env                # LM Studio has no auth

    # A MagicDNS name and a custom port must work as well as a raw IP.
    monkeypatch.setenv("TAILSCALE_LMSTUDIO_HOST", "gpu-box.tail1a2b.ts.net")
    monkeypatch.setenv("TAILSCALE_LMSTUDIO_PORT", "1235")
    p = load_config(str(example)).providers["lmstudio_tailscale"]
    assert p.base_url == "http://gpu-box.tail1a2b.ts.net:1235/v1"


def test_unset_tailscale_host_degrades_with_a_hint_not_a_crash():
    """Unset must not break startup for everyone else, but must be diagnosable.

    Every provider in the file is parsed on every load, so a fallback-less
    ${VAR} here would stop the API for people using a local model. Instead the
    URL is visibly wrong and setup_hint says what to do.
    """
    example = Path(__file__).resolve().parents[1] / "config" / "api.example.yaml"
    cfg = load_config(str(example))          # no TAILSCALE_* set

    p = cfg.providers["lmstudio_tailscale"]
    assert "tailscale-host-not-set" in p.base_url
    assert "TAILSCALE_LMSTUDIO_HOST" in p.setup_hint
    assert p.public()["setup_hint"] == p.setup_hint  # reaches the UI
    assert "\n" not in p.setup_hint                  # one clean line to display
    # ...and the rest of the configuration is unaffected.
    assert cfg.providers["lmstudio"].base_url == "http://localhost:1234/v1"


def test_failed_probe_prefers_the_provider_setup_hint(client, monkeypatch):
    """A timeout on a remote endpoint should say what to fix, not restate it."""
    from review_api import app as app_mod

    cfg = client.application.config["API_CONFIG"]
    cfg.providers["onprem"].setup_hint = "Set TAILSCALE_LMSTUDIO_HOST in .env."
    monkeypatch.setattr(app_mod.llm, "make_client",
                        lambda: (_ for _ in ()).throw(OSError("timed out")))

    probe = client.get("/api/v1/health?probe=1&provider=onprem").get_json()["probe"]
    assert probe["reachable"] is False
    assert probe["hint"] == "Set TAILSCALE_LMSTUDIO_HOST in .env."
    assert probe["base_url"] == "http://localhost:1234/v1"


# ---------------- per-request endpoint (the "endpoint address" box) --------

@pytest.mark.parametrize("typed, expected", [
    ("100.83.14.22", "http://100.83.14.22:1234/v1"),
    ("100.83.14.22:1234", "http://100.83.14.22:1234/v1"),
    ("  100.83.14.22  ", "http://100.83.14.22:1234/v1"),
    ("http://100.83.14.22", "http://100.83.14.22:1234/v1"),
    ("http://100.83.14.22:1234/v1", "http://100.83.14.22:1234/v1"),
    ("http://100.83.14.22:1234/v1/", "http://100.83.14.22:1234/v1"),
    ("gpu-box.tailnet.ts.net:1235", "http://gpu-box.tailnet.ts.net:1235/v1"),
    ("https://gpu.internal/openai/v1", "https://gpu.internal/openai/v1"),
])
def test_endpoint_normalization_accepts_what_people_actually_type(typed, expected):
    """People paste an address, not a URL. Every form must resolve the same."""
    assert normalize_endpoint(typed) == expected


@pytest.mark.parametrize("bad", ["", "   ", "ftp://host/v1", "http://u:p@host/v1"])
def test_endpoint_normalization_rejects_junk(bad):
    with pytest.raises(EndpointError):
        normalize_endpoint(bad)


def test_endpoint_must_resolve_into_an_allowed_network():
    """SSRF boundary: the server must not be steerable at arbitrary hosts.

    Without this the request body chooses where repository source code gets
    POSTed — an exfiltration channel, and a pivot into anything the server
    can reach. Private and Tailscale ranges cover the intended use; the
    configured cloud providers cover hosted models.
    """
    # Tailscale (CGNAT) and RFC 1918 are the point of the feature.
    for ok in ("http://100.83.14.22:1234/v1", "http://192.168.1.50:1234/v1",
               "http://127.0.0.1:1234/v1"):
        assert check_endpoint_allowed(ok)

    with pytest.raises(EndpointError, match="outside the networks"):
        check_endpoint_allowed("http://8.8.8.8:1234/v1")

    # 169.254.169.254 is cloud instance metadata — the classic SSRF target.
    with pytest.raises(EndpointError, match="outside the networks"):
        check_endpoint_allowed("http://169.254.169.254/v1")

    with pytest.raises(EndpointError, match="Cannot resolve"):
        check_endpoint_allowed("http://no-such-host.invalid:1234/v1")


def test_review_runs_against_a_caller_supplied_endpoint(client, monkeypatch):
    """The address typed in the console must reach the LLM client."""
    seen = {}

    def spy_review(manifest, prompt, progress=None, mode="brief", **_):
        seen["base_url"] = settings.lm_base_url
        if progress:
            progress(1, 1, "done")
        return {"repo_url": manifest["repo_url"], "commit": "f1x7ure0",
                "model": "m", "generated_at": "now", "mode": mode,
                "stats": {"files_reviewed": 1, "files_failed": 0,
                          "files_skipped": 0, "issues_total": 0,
                          "issues_by_severity": {}, "average_score": 8},
                "overall": {"summary": "ok", "score": 8, "key_issues": []},
                "reviews": [], "failures": [], "skipped": []}

    monkeypatch.setattr(pipeline, "review_manifest", spy_review)

    body = client.post("/api/v1/reviews", json={
        "review_id": "EP-01", "repo_url": "https://github.com/o/r",
        "endpoint": "192.168.7.7:9999"}).get_json()

    assert body["endpoint"] == "http://192.168.7.7:9999/v1"
    _wait(client, "EP-01")
    # The override reached the client, beating the provider's own base_url.
    assert seen["base_url"] == "http://192.168.7.7:9999/v1"
    # ...and did not leak into the process-wide settings afterwards.
    assert settings.lm_base_url != "http://192.168.7.7:9999/v1"


def test_bad_endpoint_fails_the_request_not_the_review(client):
    """Ten minutes into a review is the wrong time to learn the URL is wrong."""
    r = client.post("/api/v1/reviews", json={
        "review_id": "EP-02", "repo_url": "https://github.com/o/r",
        "endpoint": "8.8.8.8"})
    assert r.status_code == 400
    body = r.get_json()
    assert "outside the networks" in body["detail"]
    assert "100.83.14.22" in body["hint"]          # shows the expected shape
    # Nothing was started.
    assert client.get("/api/v1/reviews/EP-02").status_code == 404


def test_dry_run_reports_the_endpoint_it_would_use(client):
    body = client.post("/api/v1/reviews", json={
        "review_id": "EP-03", "repo_url": "https://github.com/o/r",
        "endpoint": "10.1.2.3", "dry_run": True}).get_json()
    assert body["endpoint"] == "http://10.1.2.3:1234/v1"
    assert body["endpoint_override"] == "http://10.1.2.3:1234/v1"

    plain = client.post("/api/v1/reviews", json={
        "review_id": "EP-04", "repo_url": "https://github.com/o/r",
        "dry_run": True}).get_json()
    assert plain["endpoint_override"] is None      # provider default in use


def test_custom_endpoint_can_be_switched_off(tmp_path, monkeypatch):
    """An operator must be able to allow only the configured providers."""
    from review_api.app import create_app

    cfg = _cfg(tmp_path)
    cfg.allow_custom_endpoint = False
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())
    c = create_app(cfg=cfg).test_client()

    assert c.get("/api/v1/config").get_json()["allow_custom_endpoint"] is False
    r = c.post("/api/v1/reviews", json={
        "review_id": "EP-05", "repo_url": "https://github.com/o/r",
        "endpoint": "10.1.2.3"})
    assert r.status_code == 400
    assert "does not accept a custom endpoint" in r.get_json()["detail"]


def test_probe_accepts_an_endpoint_so_it_can_be_tested_first(client, monkeypatch):
    """The console's Test button: check the address before using it."""
    from review_api import app as app_mod

    class FakeModels:
        def list(self):
            return type("R", (), {"data": [type("M", (), {"id": "gemma-x"})()]})()

    seen = {}

    def fake_client():
        seen["base_url"] = settings.lm_base_url
        return type("C", (), {"models": FakeModels()})()

    monkeypatch.setattr(app_mod.llm, "make_client", fake_client)

    probe = client.get(
        "/api/v1/health?probe=1&endpoint=100.100.5.5").get_json()["probe"]
    assert probe["reachable"] is True
    assert probe["endpoint_override"] == "http://100.100.5.5:1234/v1"
    assert seen["base_url"] == "http://100.100.5.5:1234/v1"
    assert probe["models"] == ["gemma-x"]

    bad = client.get("/api/v1/health?probe=1&endpoint=8.8.8.8").get_json()["probe"]
    assert bad["reachable"] is False and "outside the networks" in bad["error"]


def test_repo_access_route_works_and_forwards_a_token(client, monkeypatch):
    """Regression: this route 500'd on every call.

    `check_access` had no `token` parameter while the route passed one, so
    `TypeError: unexpected keyword argument 'token'` reached the client as a
    bare HTML 500 — and no test exercised the route, only the function under
    it. Found by writing the client guide against a running server.
    """
    from review_api import app as app_mod

    seen = {}

    def fake_check(repo_url, branch=None, token=None):
        seen.update(repo_url=repo_url, branch=branch, token=token)
        return {"repo_url": repo_url, "status": "ok", "branches_found": 3,
                "authenticated": bool(token)}

    monkeypatch.setattr(app_mod, "check_access", fake_check)

    r = client.get("/api/v1/repo-access?repo_url=https://github.com/o/r")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"
    assert seen == {"repo_url": "https://github.com/o/r", "branch": None,
                    "token": None}

    # A per-request token must reach the check, so a caller can verify the
    # credential it is about to review with.
    r = client.get("/api/v1/repo-access?repo_url=https://github.com/o/r"
                   "&branch=dev", headers={"X-Repo-Token": TOKEN})
    assert r.status_code == 200
    assert seen["token"] == TOKEN and seen["branch"] == "dev"
    assert TOKEN not in r.get_data(as_text=True)      # never echoed back


def test_check_access_signature_matches_how_the_route_calls_it():
    """Cheap guard against the two drifting apart again."""
    import inspect

    from code_review_mcp.repo_ingest import check_access

    params = inspect.signature(check_access).parameters
    assert {"repo_url", "branch", "token"} <= set(params)


# ---------------- model discovery (the model dropdown) ---------------------

def _fake_llm(monkeypatch, models, seen=None):
    """Point the shared LLM client at a fake that lists `models`."""
    from review_api import app as app_mod

    class FakeModels:
        def list(self):
            return type("R", (), {
                "data": [type("M", (), {"id": m})() for m in models]})()

    def fake_client():
        if seen is not None:
            seen["base_url"] = settings.lm_base_url
            seen["api_key"] = settings.lm_api_key
        return type("C", (), {"models": FakeModels()})()

    monkeypatch.setattr(app_mod.llm, "make_client", fake_client)


def test_models_endpoint_lists_what_the_provider_serves(client, monkeypatch):
    seen = {}
    _fake_llm(monkeypatch, ["zeta-1", "alpha-9", "mid-4"], seen)

    body = client.get("/api/v1/models?provider=onprem").get_json()
    assert body["reachable"] is True
    # Sorted, so the dropdown is not in arbitrary server order.
    assert body["models"] == ["alpha-9", "mid-4", "zeta-1"]
    assert body["model_count"] == 3
    assert body["default_model"] == "local-model"   # marked in the picker
    assert seen["base_url"] == "http://localhost:1234/v1"


def test_models_endpoint_returns_everything_the_health_probe_trims(client,
                                                                   monkeypatch):
    """A cloud provider can offer dozens; the picker must show them all."""
    many = [f"model-{i:03d}" for i in range(60)]
    _fake_llm(monkeypatch, many)

    assert len(client.get("/api/v1/models?provider=cloud").get_json()["models"]) == 60
    # The health payload stays a preview.
    probe = client.get("/api/v1/health?probe=1&provider=cloud").get_json()["probe"]
    assert len(probe["models"]) == 25 and probe["model_count"] == 60


def test_models_endpoint_honours_a_custom_endpoint(client, monkeypatch):
    seen = {}
    _fake_llm(monkeypatch, ["gemma-remote"], seen)

    body = client.get("/api/v1/models?endpoint=100.83.14.22").get_json()
    assert body["models"] == ["gemma-remote"]
    assert body["endpoint_override"] == "http://100.83.14.22:1234/v1"
    assert seen["base_url"] == "http://100.83.14.22:1234/v1"

    # ...and the same SSRF boundary applies here as everywhere else.
    bad = client.get("/api/v1/models?endpoint=8.8.8.8").get_json()
    assert bad["reachable"] is False and "outside the networks" in bad["error"]


def test_unreachable_provider_is_not_a_client_error(client, monkeypatch):
    """The picker must degrade to "type an id", not render a failure."""
    from review_api import app as app_mod
    monkeypatch.setattr(app_mod.llm, "make_client",
                        lambda: (_ for _ in ()).throw(OSError("refused")))

    r = client.get("/api/v1/models?provider=onprem")
    assert r.status_code == 200                  # upstream state, not our fault
    body = r.get_json()
    assert body["reachable"] is False
    assert body["models"] == [] and body["model_count"] == 0
    assert body["default_model"] == "local-model"   # still offerable
    assert body["hint"]


def test_chosen_model_reaches_the_pipeline(client, monkeypatch):
    """Picking from the dropdown must actually route the review."""
    seen = {}

    def spy(manifest, prompt, progress=None, mode="brief", **_):
        seen["model"] = settings.lm_model
        if progress:
            progress(1, 1, "done")
        return {"repo_url": manifest["repo_url"], "commit": "c", "model": "m",
                "generated_at": "now", "mode": mode,
                "stats": {"files_reviewed": 1, "files_failed": 0,
                          "files_skipped": 0, "issues_total": 0,
                          "issues_by_severity": {}, "average_score": 8},
                "overall": {"summary": "ok", "score": 8, "key_issues": []},
                "reviews": [], "failures": [], "skipped": []}

    monkeypatch.setattr(pipeline, "review_manifest", spy)
    client.post("/api/v1/reviews", json={
        "review_id": "MODEL-01", "repo_url": "https://github.com/o/r",
        "model": "gemma-picked-from-list"})
    _wait(client, "MODEL-01")
    assert seen["model"] == "gemma-picked-from-list"


# ---------------- cloud + on-prem routing ----------------

def test_providers_endpoint_lists_cloud_and_on_prem(client):
    body = client.get("/api/v1/providers").get_json()
    locations = {p["name"]: p["location"] for p in body["providers"]}
    assert locations == {"onprem": "on_prem", "cloud": "cloud"}
    assert body["default"] == "onprem"


def test_review_can_target_a_specific_provider(client, monkeypatch):
    seen = {}
    real = pipeline.review_manifest

    def spy(manifest, prompt, progress=None, mode="brief", **kw):
        from code_review_mcp.config import settings
        seen["base_url"] = settings.lm_base_url
        seen["model"] = settings.lm_model
        return real(manifest, prompt, progress, mode, **kw)

    monkeypatch.setattr(pipeline, "review_manifest", spy)
    client.post("/api/v1/reviews", json={
        "review_id": "P-1", "repo_url": "https://github.com/o/r",
        "provider": "cloud", "model": "gpt-x"})
    _wait(client, "P-1")
    # The per-request provider really is what the LLM client points at.
    assert seen["base_url"] == "https://api.example.com/v1"
    assert seen["model"] == "gpt-x"


def test_unknown_provider_is_rejected(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "P-2", "repo_url": "https://github.com/o/r",
        "provider": "nope"})
    assert r.status_code == 400
    assert "Unknown provider" in r.get_json()["detail"]


# ---------------- requirement 2: prompt consolidation ----------------

def test_build_prompt_consolidates_everything():
    info = build_prompt(
        mode="deep", repo_url="https://github.com/o/r", review_id="R1",
        persona_name="security", persona_prompt="You are an auditor.",
        focus=["authentication", "secrets"],
        findings_summary={"findings_total": 3, "source": "semgrep"},
        files=["settings.py"])
    prompt = info["system_prompt"]
    assert "You are an auditor." in prompt
    assert "DEEP per-file review" in prompt
    assert "authentication; secrets" in prompt
    assert "ENRICHMENT" in prompt              # findings present -> duty added
    assert "UNTRUSTED DATA" in prompt          # standing safety rule
    assert info["context"]["files_scope"] == ["settings.py"]
    assert info["template_version"]


def test_prompt_omits_enrichment_without_findings():
    info = build_prompt(mode="brief", repo_url="r", review_id="R2",
                        persona_prompt="Reviewer.")
    assert "ENRICHMENT" not in info["system_prompt"]


def test_dry_run_returns_prompt_without_running(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "DRY-1", "repo_url": "https://github.com/o/r",
        "mode": "deep", "focus": ["crypto"], "dry_run": True})
    body = r.get_json()
    assert body["status"] == "dry_run"
    assert "crypto" in body["prompt"]["system_prompt"]
    # Nothing was started.
    assert client.get("/api/v1/reviews/DRY-1").status_code == 404


def test_create_returns_prompt_and_prompt_endpoint(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "PR-1", "repo_url": "https://github.com/o/r"})
    assert r.status_code == 202
    assert "system_prompt" in r.get_json()["prompt"]
    _wait(client, "PR-1")
    stored = client.get("/api/v1/reviews/PR-1/prompt").get_json()
    assert stored["prompt"]["system_prompt"]


def test_custom_system_prompt_overrides_persona(client):
    body = client.post("/api/v1/reviews", json={
        "review_id": "SP-1", "repo_url": "https://github.com/o/r",
        "system_prompt": "ONLY look for race conditions.",
        "dry_run": True}).get_json()
    assert "ONLY look for race conditions." in body["prompt"]["system_prompt"]
    assert "security auditor" not in body["prompt"]["system_prompt"]


# ---------------- requirement 1 + 3: intake and progress ----------------

def test_review_lifecycle_and_progress(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "LC-1", "repo_url": "https://github.com/o/r",
        "mode": "brief"})
    assert r.status_code == 202
    body = r.get_json()
    # `action` is the HTTP outcome; `status` is the review's live state, so it
    # may already have advanced past "requested" by the time we serialize.
    assert body["action"] == "accepted" and body["review_id"] == "LC-1"
    assert body["status"] in ("requested", "cloning", "reviewing", "completed")

    done = _wait(client, "LC-1")
    assert done["status"] == "completed"
    assert done["percent"] == 100
    assert "batches done" in done["progress"]
    assert done["stats"]["files_reviewed"] == 6
    assert done["report"]["json"].endswith("LC-1.json")

    summary = client.get("/api/v1/reviews/LC-1/report").get_json()
    assert summary["stats"]["files_reviewed"] == 6
    assert len(summary["files"]) == 6
    full = client.get("/api/v1/reviews/LC-1/report?view=full").get_json()
    assert full["mode"] == "brief"


def test_validation_errors(client):
    assert client.post("/api/v1/reviews", json={}).status_code == 400
    assert client.post("/api/v1/reviews", json={
        "review_id": "X"}).status_code == 400
    bad_mode = client.post("/api/v1/reviews", json={
        "review_id": "X", "repo_url": "https://github.com/o/r",
        "mode": "turbo"})
    assert bad_mode.status_code == 400
    assert "mode must be one of" in bad_mode.get_json()["detail"]


def test_missing_findings_file_rejected_at_request_time(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "F-1", "repo_url": "https://github.com/o/r",
        "findings_file": "nope.json"})
    assert r.status_code == 400
    assert "not found" in r.get_json()["detail"]


def test_findings_file_is_consolidated_into_the_prompt(client, tmp_path):
    (tmp_path / "scan.json").write_text(json.dumps({
        "source": "semgrep",
        "findings": [{"file": "app/main.py", "rule": "dangerous-eval",
                      "severity": "high", "line": 13, "description": "eval"}],
    }), encoding="utf-8")
    body = client.post("/api/v1/reviews", json={
        "review_id": "F-2", "repo_url": "https://github.com/o/r",
        "findings_file": "scan.json", "mode": "deep",
        "dry_run": True}).get_json()
    assert "ENRICHMENT" in body["prompt"]["system_prompt"]
    ctx = body["prompt"]["context"]["deterministic_findings"]
    assert ctx["findings_total"] == 1 and ctx["source"] == "semgrep"


def test_one_review_at_a_time(client, monkeypatch):
    gate = {"go": False}

    def slow(manifest, prompt, progress=None, mode="brief", **_):
        while not gate["go"]:
            time.sleep(0.02)
        return {"stats": {}, "reviews": [], "failures": [], "skipped": [],
                "mode": mode, "repo_url": "r", "commit": "c", "model": "m",
                "generated_at": "n"}

    monkeypatch.setattr(pipeline, "review_manifest", slow)
    first = client.post("/api/v1/reviews", json={
        "review_id": "B-1", "repo_url": "https://github.com/o/r"})
    second = client.post("/api/v1/reviews", json={
        "review_id": "B-2", "repo_url": "https://github.com/o/r"})
    gate["go"] = True
    assert first.status_code == 202
    assert second.status_code == 409
    assert second.get_json()["status"] == "busy"


def test_both_409s_carry_the_same_discriminator(client, monkeypatch):
    """Two different 409s meant two different response shapes, and a client
    told them apart by which keys were missing — then crashed to a 500 when
    it read `review_id` off the busy one.

    `action` now names the outcome on both, so nobody has to infer it from
    absence. `review_id` stays off the busy body until that consumer has
    moved over: it is currently their discriminator, and adding it early
    would break the very client this is meant to help.
    """
    gate = {"go": False}

    def slow(manifest, prompt, progress=None, mode="brief", **_):
        while not gate["go"]:
            time.sleep(0.02)
        return {"stats": {}, "reviews": [], "failures": [], "skipped": [],
                "mode": mode, "repo_url": "r", "commit": "c", "model": "m",
                "generated_at": "n"}

    monkeypatch.setattr(pipeline, "review_manifest", slow)
    first = client.post("/api/v1/reviews", json={
        "review_id": "A-1", "repo_url": "https://github.com/o/r"})
    assert first.status_code == 202
    try:
        same = client.post("/api/v1/reviews", json={
            "review_id": "A-1", "repo_url": "https://github.com/o/r"})
        other = client.post("/api/v1/reviews", json={
            "review_id": "A-2", "repo_url": "https://github.com/o/r"})

        assert (same.status_code, other.status_code) == (409, 409)
        assert same.get_json()["action"] == "already_running"
        assert other.get_json()["action"] == "busy"
        # The occupying review is still identifiable from the busy body.
        assert other.get_json()["active"]["review_id"] == "A-1"
        assert "review_id" not in other.get_json()
    finally:
        gate["go"] = True
        _wait(client, "A-1")


def test_a_forgotten_review_with_a_checkpoint_reads_as_interrupted(
        client, tmp_path):
    """The registry forgot it (an API restart); the checkpoint did not. It
    used to be a 404 that only hinted at resuming."""
    (tmp_path / "GHOST.partial.json").write_text(json.dumps({
        "repo_url": "https://github.com/o/r", "mode": "brief",
        "progress": {"done": 2, "total": 9}}), encoding="utf-8")
    r = client.get("/api/v1/reviews/GHOST")
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "interrupted" and body["source"] == "disk"
    assert body["resumable"] is True
    assert (body["done"], body["total"], body["percent"]) == (2, 9, 22)


def test_an_unknown_review_still_lists_resumable_checkpoints(client,
                                                             tmp_path):
    (tmp_path / "GHOST.partial.json").write_text(json.dumps({
        "repo_url": "https://github.com/o/r", "mode": "brief",
        "progress": {"done": 2, "total": 9}}), encoding="utf-8")
    r = client.get("/api/v1/reviews/NOBODY")
    assert r.status_code == 404
    body = r.get_json()
    assert body["resumable_checkpoints"][0]["review_id"] == "GHOST"
    assert "resume" in body["hint"]


# ---------------- requirement 4: restart after failure ----------------

def test_failed_review_is_restartable_and_resumes(client, monkeypatch,
                                                  tmp_path):
    """A crashed review keeps its checkpoint; restart reuses completed units."""
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 300)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 250)
    monkeypatch.setattr(pipeline, "review_manifest",
                        review_mod.review_manifest)  # real batching + ckpt

    calls = []

    def dying(client_, prompt, digest, heartbeat=None):
        if digest["task"] == "brief_repository_review":
            calls.append(1)
            if len(calls) == 2:
                raise LLMUnavailableError("model died mid-batch")
        return {"summary": "ok", "score": 6, "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", dying)
    client.post("/api/v1/reviews", json={
        "review_id": "RS-1", "repo_url": "https://github.com/o/r",
        "mode": "brief"})
    failed = _wait(client, "RS-1")
    assert failed["status"] == "failed"
    assert failed["restartable"] is True
    assert "died" in failed["error"]
    assert (tmp_path / "RS-1.partial.json").is_file()   # checkpoint survived

    healthy = []

    def ok(client_, prompt, digest, heartbeat=None):
        if digest["task"] == "brief_repository_review":
            healthy.append(1)
        return {"summary": "ok", "score": 7, "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", ok)
    r = client.post("/api/v1/reviews/RS-1/restart")
    assert r.status_code == 202
    assert r.get_json()["action"] == "restarted"
    done = _wait(client, "RS-1")
    assert done["status"] == "completed"
    assert done["attempts"] == 2
    assert done["restored_units"] >= 1                  # reused batch 0
    report = json.loads((tmp_path / "RS-1.json").read_text(encoding="utf-8"))
    assert report["resumed"] is True
    assert not (tmp_path / "RS-1.partial.json").exists()


def test_restart_rejected_while_running(client, monkeypatch):
    gate = {"go": False}
    monkeypatch.setattr(pipeline, "review_manifest",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("unused")) if gate["go"] else
                        _block(gate))
    client.post("/api/v1/reviews", json={
        "review_id": "RJ-1", "repo_url": "https://github.com/o/r"})
    time.sleep(0.1)
    r = client.post("/api/v1/reviews/RJ-1/restart")
    gate["go"] = True
    assert r.status_code == 409


def _block(gate):
    while not gate["go"]:
        time.sleep(0.02)
    return {"stats": {}, "reviews": [], "failures": [], "skipped": [],
            "mode": "brief", "repo_url": "r", "commit": "c", "model": "m",
            "generated_at": "n"}


def test_restart_of_unknown_review_is_404(client):
    assert client.post("/api/v1/reviews/NOPE/restart").status_code == 404


# ---------------- pause and resume ----------------

SHA = "a" * 40


def _brief_with_real_checkpoints(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 300)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 250)
    monkeypatch.setattr(pipeline, "review_manifest",
                        review_mod.review_manifest)
    ingests = []

    def ingest(*a, **k):
        ingests.append(k)
        return {**dummy_manifest(), "commit": SHA}

    monkeypatch.setattr(pipeline, "ingest_repository", ingest)
    return review_mod, ingests


def test_pause_survives_a_restart_and_resume_continues_pinned(
        client, monkeypatch, tmp_path):
    """The whole feature: pause a running review, lose the API's memory,
    come back, resume - the checkpoint is reused, at the same commit."""
    review_mod, ingests = _brief_with_real_checkpoints(monkeypatch)
    store = client.application.config["JOB_STORE"]
    batches = []

    def pause_after_first(client_, prompt, digest, heartbeat=None):
        if digest["task"] == "brief_repository_review":
            batches.append(1)
            if len(batches) == 1:
                # The user clicks Pause while batch 1 is in flight.
                assert store.pause(store.get("P-1"))
        return {"summary": "ok", "score": 6, "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", pause_after_first)
    r = client.post("/api/v1/reviews", json={
        "review_id": "P-1", "repo_url": "https://github.com/dummy/dummy-repo",
        "mode": "brief", "branch": "main"})
    assert r.status_code == 202
    paused = _wait(client, "P-1", want=("paused",))
    assert paused["resumable"] is True and paused["pausable"] is False
    assert paused["paused_at"]
    marker = json.loads((tmp_path / "P-1.paused.json").read_text("utf-8"))
    assert marker["commit"] == SHA and marker["branch"] == "main"
    assert "token" not in json.dumps(marker)
    assert (tmp_path / "P-1.partial.json").is_file()

    # Days later: a new process, an empty registry.
    from review_api.app import create_app
    fresh = create_app(cfg=_cfg(tmp_path)).test_client()
    seen = fresh.get("/api/v1/reviews/P-1").get_json()
    assert (seen["status"], seen["source"]) == ("paused", "disk")
    assert seen["commit"] == SHA

    monkeypatch.setattr(review_mod, "review_digest",
                        lambda c, p, d, heartbeat=None: {
                            "summary": "ok", "score": 7, "key_issues": [],
                            "files": []})
    r = fresh.post("/api/v1/reviews/P-1/resume",
                   headers={"X-Repo-Token": "ghp_fresh"})
    assert r.status_code == 202, r.get_json()
    body = r.get_json()
    assert body["action"] == "resumed" and body["restored_units"] >= 1
    assert body["pinned_commit"] == SHA
    done = _wait(fresh, "P-1")
    assert done["status"] == "completed" and done["restored_units"] >= 1
    assert ingests[-1]["commit"] == SHA               # pinned, not the tip
    assert ingests[-1]["token"] == "ghp_fresh"        # the new session's token
    assert not (tmp_path / "P-1.paused.json").exists()
    assert "ghp_fresh" not in json.dumps(done)


def test_pausing_twice_and_pausing_a_finished_review(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "P-2", "repo_url": "https://github.com/o/r"})
    assert r.status_code == 202
    _wait(client, "P-2")
    r = client.post("/api/v1/reviews/P-2/pause")
    assert r.status_code == 409                       # nothing left to pause
    assert client.post("/api/v1/reviews/NOPE/pause").status_code == 404


def test_resume_of_a_finished_review_is_refused(client):
    client.post("/api/v1/reviews", json={
        "review_id": "P-3", "repo_url": "https://github.com/o/r"})
    _wait(client, "P-3")
    assert client.post("/api/v1/reviews/P-3/resume").status_code == 409


def test_resume_without_any_record_needs_a_repo_url(client, tmp_path):
    assert client.post("/api/v1/reviews/P-4/resume").status_code == 404
    # The gateway sends what it stored, for a review paused before the
    # first checkpoint: then it simply starts over.
    r = client.post("/api/v1/reviews/P-4/resume", json={
        "repo_url": "https://github.com/o/r", "mode": "brief"})
    assert r.status_code == 202
    assert r.get_json()["restored_units"] == 0
    assert _wait(client, "P-4")["status"] == "completed"


def test_a_bad_commit_is_refused_on_start(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "P-5", "repo_url": "https://github.com/o/r",
        "commit": "abc"})
    assert r.status_code == 400


def test_a_review_still_written_by_a_detached_job_is_not_resumable(
        client, tmp_path):
    """review-api restarted while a Job kept running: resuming would start
    a second worker on the same checkpoint."""
    (tmp_path / "D-1.progress.json").write_text(json.dumps({
        "phase": "reviewing", "done": 3, "total": 10,
        "updated_at": time.time()}), encoding="utf-8")
    body = client.get("/api/v1/reviews/D-1").get_json()
    assert body["status"] == "reviewing" and body["detached"] is True
    assert body["percent"] == 30
    assert client.post("/api/v1/reviews/D-1/resume").status_code == 409
    assert client.post("/api/v1/reviews/D-1/pause").status_code == 409


def test_restart_falls_back_to_resume_for_a_forgotten_review(client,
                                                             tmp_path):
    """POST /restart was a 404 here (and a 500 in kubernetes mode)."""
    (tmp_path / "F-1.partial.json").write_text(json.dumps({
        "repo_url": "https://github.com/o/r", "mode": "brief",
        "commit": SHA, "progress": {"done": 1, "total": 3},
        "batch_results": {"0": {}}}), encoding="utf-8")
    r = client.post("/api/v1/reviews/F-1/restart")
    assert r.status_code == 202
    assert r.get_json()["action"] == "resumed"
    _wait(client, "F-1")


# ---------------- requirement 5: private-repo token routing ----------------

def test_access_token_reaches_the_clone_but_nothing_else(client, monkeypatch,
                                                        tmp_path, caplog):
    """The token must reach ingest, and appear NOWHERE else."""
    seen = {}

    def spy_ingest(repo_url, branch, extensions, token=None, **kwargs):
        seen["token"] = token
        return dummy_manifest()

    monkeypatch.setattr(pipeline, "ingest_repository", spy_ingest)

    with caplog.at_level(logging.DEBUG):
        created = client.post("/api/v1/reviews", json={
            "review_id": "TOK-1", "repo_url": "https://github.com/o/private",
            "access_token": TOKEN}).get_json()
        done = _wait(client, "TOK-1")

    # It got where it was needed...
    assert seen["token"] == TOKEN
    # ...and nowhere else: not in the create response, the status, the list,
    # the report, or the logs.
    assert TOKEN not in json.dumps(created)
    assert TOKEN not in json.dumps(done)
    assert created["authenticated"] is True and done["private_repo"] is True
    assert TOKEN not in json.dumps(
        client.get("/api/v1/reviews").get_json())
    assert TOKEN not in (tmp_path / "TOK-1.json").read_text(encoding="utf-8")
    assert all(TOKEN not in r.getMessage() for r in caplog.records)


def test_token_accepted_via_header_too(client, monkeypatch):
    seen = {}
    monkeypatch.setattr(
        pipeline, "ingest_repository",
        lambda repo_url, branch, extensions, token=None, **kwargs:
        (seen.update(token=token), dummy_manifest())[1])
    client.post("/api/v1/reviews",
                json={"review_id": "TOK-2",
                      "repo_url": "https://github.com/o/private"},
                headers={"X-Repo-Token": TOKEN})
    _wait(client, "TOK-2")
    assert seen["token"] == TOKEN


def test_token_is_dropped_after_the_review(client, monkeypatch):
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())
    client.post("/api/v1/reviews", json={
        "review_id": "TOK-3", "repo_url": "https://github.com/o/private",
        "access_token": TOKEN})
    _wait(client, "TOK-3")
    store = client.application.config["JOB_STORE"]
    assert store._tokens == {}          # noqa: SLF001 - asserting cleanup


def test_public_review_sends_no_token(client, monkeypatch):
    seen = {}

    def spy(repo_url, branch, extensions, **kwargs):
        seen["kwargs"] = kwargs
        return dummy_manifest()

    monkeypatch.setattr(pipeline, "ingest_repository", spy)
    client.post("/api/v1/reviews", json={
        "review_id": "PUB-1", "repo_url": "https://github.com/o/public"})
    _wait(client, "PUB-1")
    # The credential kwarg is always PASSED, and is None for a public repo.
    # It used to be omitted entirely, which is exactly what hid the fact that
    # ingest_repository had no `token` parameter at all until a private
    # review tried to use it.
    assert seen["kwargs"]["token"] is None


# ---------------- API surface / auth ----------------

def test_health_and_config_expose_no_secrets(client, monkeypatch):
    monkeypatch.setenv("EXAMPLE_API_KEY", "sk-should-not-appear")
    health = client.get("/api/v1/health").get_json()
    assert health["status"] == "ok"
    cfg = client.get("/api/v1/config").get_json()
    assert "sk-should-not-appear" not in json.dumps(cfg)
    assert cfg["providers"][1]["api_key_configured"] is True


def test_api_key_enforced_when_configured(tmp_path, monkeypatch):
    from review_api.app import create_app

    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())
    cfg = _cfg(tmp_path)
    cfg.api_key = "s3cret"
    app = create_app(cfg=cfg)
    c = app.test_client()
    assert c.get("/api/v1/config").status_code == 401
    assert c.get("/api/v1/config",
                 headers={"X-API-Key": "s3cret"}).status_code == 200
    # The descriptor and the probes answer without a key; a kubelet sends none.
    assert c.get("/").status_code == 200
    assert c.get("/healthz").status_code == 200


def test_reports_listing_includes_checkpoints(client, tmp_path):
    (tmp_path / "R.json").write_text("{}", encoding="utf-8")
    (tmp_path / "R2.partial.json").write_text(json.dumps(
        {"repo_url": "r", "mode": "deep",
         "progress": {"done": 1, "total": 5}}), encoding="utf-8")
    body = client.get("/api/v1/reports").get_json()
    assert "R.json" in [r["name"] for r in body["reports"]]
    assert body["resumable_checkpoints"][0]["review_id"] == "R2"


# ---------------- report management: list all, get one, delete one ----------

def _write_report(dir_path: Path, review_id: str, *, issues=0,
                  markdown=True, notes=False, checkpoint=False) -> Path:
    """A realistic report on disk, plus whichever sidecars are asked for."""
    target = dir_path / f"{review_id}.json"
    target.write_text(json.dumps({
        "repo_url": "https://github.com/owner/repo", "branch": "labs",
        "commit": "ac0fec4e77a8", "model": "google/gemma-4-26b-a4b-qat",
        "mode": "deep", "generated_at": "2026-08-17T09:00:00Z",
        "stats": {"files_reviewed": 34, "files_failed": 0, "files_skipped": 0,
                  "files_excluded": 3, "issues_total": issues,
                  "issues_by_severity": {"critical": issues, "high": 0,
                                         "medium": 0, "low": 0, "info": 0},
                  "average_score": 4},
        "overall": {"summary": "Needs work.", "score": 4, "key_issues": []},
        "excluded": {"count": 3, "by_type": {".md": 3}, "examples": []},
        "reviews": [{"file": "server.js", "summary": "ok", "score": 4,
                     "issues": [{"severity": "critical", "line": 69,
                                 "title": "path traversal"}][:issues]}],
        "failures": [], "skipped": [],
    }), encoding="utf-8")
    if markdown:
        (dir_path / f"{review_id}.md").write_text(f"# {review_id}\n",
                                                  encoding="utf-8")
    if notes:
        (dir_path / f"{review_id}.notes.md").write_text("notes",
                                                        encoding="utf-8")
    if checkpoint:
        (dir_path / f"{review_id}.partial.json").write_text(json.dumps(
            {"repo_url": "https://github.com/owner/repo", "mode": "deep",
             "progress": {"done": 4, "total": 34}}), encoding="utf-8")
    return target


def test_listing_all_reports_carries_headline_facts(client, tmp_path):
    _write_report(tmp_path, "DEMO-01", issues=1)
    body = client.get("/api/v1/reports").get_json()

    assert body["count"] == 1
    entry = body["reports"][0]
    assert entry["name"] == "DEMO-01.json"
    assert entry["review_id"] == "DEMO-01"
    assert entry["readable"] is True
    assert entry["repo_url"] == "https://github.com/owner/repo"
    assert entry["commit"] == "ac0fec4e77a8"
    assert entry["mode"] == "deep"
    assert (entry["files_reviewed"], entry["issues_total"]) == (34, 1)
    assert entry["files_excluded"] == 3     # coverage travels with the listing
    assert entry["score"] == 4
    assert entry["has_markdown"] is True
    assert entry["is_report"] is True
    assert entry["links"]["self"] == "/api/v1/reports/DEMO-01"
    assert entry["modified_at"].endswith("Z")


def test_non_report_json_in_the_directory_is_flagged_not_hidden(client,
                                                               tmp_path):
    """The reports dir also holds findings inputs. They stay visible — a file
    nobody expected should never silently vanish — but say what they are."""
    _write_report(tmp_path, "REAL-01")
    (tmp_path / "scan.findings.json").write_text(
        json.dumps({"results": [{"path": "a.py"}]}), encoding="utf-8")

    flags = {e["name"]: e.get("is_report")
             for e in client.get("/api/v1/reports").get_json()["reports"]}
    assert flags == {"REAL-01.json": True, "scan.findings.json": False}


def test_a_corrupt_report_does_not_break_the_listing(client, tmp_path):
    """One half-written file must not 500 the endpoint for every other."""
    _write_report(tmp_path, "GOOD-01")
    (tmp_path / "TRUNCATED.json").write_text('{"repo_url": "https://git',
                                             encoding="utf-8")
    (tmp_path / "NOTADICT.json").write_text("[1, 2, 3]", encoding="utf-8")

    r = client.get("/api/v1/reports")
    assert r.status_code == 200
    readable = {e["name"]: e["readable"] for e in r.get_json()["reports"]}
    assert readable == {"GOOD-01.json": True, "TRUNCATED.json": False,
                        "NOTADICT.json": False}


def test_listing_is_newest_first_and_respects_limit(client, tmp_path):
    import os
    for i, name in enumerate(["OLD", "MIDDLE", "NEW"]):
        path = _write_report(tmp_path, name)
        os.utime(path, (1_700_000_000 + i * 100, 1_700_000_000 + i * 100))

    body = client.get("/api/v1/reports?limit=2").get_json()
    assert [e["review_id"] for e in body["reports"]] == ["NEW", "MIDDLE"]


def test_a_junk_limit_falls_back_instead_of_500ing(client, tmp_path):
    _write_report(tmp_path, "R")
    assert client.get("/api/v1/reports?limit=abc").status_code == 200


def test_partial_checkpoints_are_not_listed_as_reports(client, tmp_path):
    _write_report(tmp_path, "R", markdown=False, checkpoint=True)
    body = client.get("/api/v1/reports").get_json()
    assert [e["name"] for e in body["reports"]] == ["R.json"]
    assert body["resumable_checkpoints"][0]["review_id"] == "R"


def test_get_one_report_by_name(client, tmp_path):
    _write_report(tmp_path, "DEMO-01", issues=1)
    body = client.get("/api/v1/reports/DEMO-01").get_json()

    assert body["report"] == "DEMO-01.json"
    assert body["commit"] == "ac0fec4e77a8"
    assert body["stats"]["files_reviewed"] == 34
    assert body["excluded"]["by_type"] == {".md": 3}
    assert body["files"] == [{"file": "server.js", "score": 4, "issues": 1}]


def test_get_one_report_tolerates_the_json_suffix(client, tmp_path):
    """`R` and `R.json` both name the same report — clients copy either."""
    _write_report(tmp_path, "R")
    plain = client.get("/api/v1/reports/R").get_json()
    suffixed = client.get("/api/v1/reports/R.json").get_json()
    assert plain == suffixed


def test_get_one_report_supports_the_same_views(client, tmp_path):
    _write_report(tmp_path, "R", issues=1)

    full = client.get("/api/v1/reports/R?view=full").get_json()
    assert full["reviews"][0]["issues"][0]["line"] == 69

    md = client.get("/api/v1/reports/R?view=markdown")
    assert md.mimetype == "text/markdown"
    assert md.get_data(as_text=True) == "# R\n"

    one = client.get("/api/v1/reports/R?file=server.js").get_json()
    assert one["file"] == "server.js"
    assert client.get("/api/v1/reports/R?file=nope.js").status_code == 404


def test_get_unknown_report_is_404(client):
    r = client.get("/api/v1/reports/NOPE")
    assert r.status_code == 404
    assert "/api/v1/reports" in r.get_json()["hint"]


def test_delete_report_removes_the_report_and_its_sidecars(client, tmp_path):
    _write_report(tmp_path, "DEMO-01", notes=True)
    r = client.delete("/api/v1/reports/DEMO-01")

    assert r.status_code == 200
    body = r.get_json()
    assert body["action"] == "deleted" and body["review_id"] == "DEMO-01"
    assert sorted(body["deleted"]) == ["DEMO-01.json", "DEMO-01.md",
                                       "DEMO-01.notes.md"]
    assert not (tmp_path / "DEMO-01.json").exists()
    assert not (tmp_path / "DEMO-01.md").exists()
    assert not (tmp_path / "DEMO-01.notes.md").exists()
    # And it is gone from the listing.
    assert client.get("/api/v1/reports").get_json()["reports"] == []


def test_worker_sidecars_are_never_listed_and_go_with_their_report(
        client, tmp_path):
    """The Job worker's <id>.error.json and <id>.progress.json (contract v2)
    are JSON files in the reports folder, so a plain *.json listing would
    show them as reports - and an error file can exist with NO report at
    all, for a review that failed permanently."""
    _write_report(tmp_path, "R")
    (tmp_path / "R.error.json").write_text(
        '{"permanent": false, "error": "retryable: x"}', encoding="utf-8")
    (tmp_path / "R.progress.json").write_text(
        '{"current_file": "", "current_started_at": null, "durations": [],'
        ' "updated_at": 0}', encoding="utf-8")
    (tmp_path / "FAILED.error.json").write_text(
        '{"permanent": true, "error": "permanent: bad branch"}',
        encoding="utf-8")

    listed = client.get("/api/v1/reports").get_json()["reports"]
    assert [r["review_id"] for r in listed] == ["R"]

    body = client.delete("/api/v1/reports/R").get_json()
    assert "R.error.json" in body["deleted"]
    assert "R.progress.json" in body["deleted"]
    assert not (tmp_path / "R.error.json").exists()
    assert not (tmp_path / "R.progress.json").exists()


def test_delete_keeps_the_resume_checkpoint_by_default(client, tmp_path):
    """A report can be regenerated; an interrupted review's checkpoint is the
    only copy of work already paid for. Removing it must be asked for."""
    _write_report(tmp_path, "R", checkpoint=True)
    body = client.delete("/api/v1/reports/R").get_json()

    assert body["checkpoint_kept"] == "R.partial.json"
    assert "restartable" in body["note"]
    assert (tmp_path / "R.partial.json").exists()


def test_delete_can_also_drop_the_checkpoint_when_asked(client, tmp_path):
    _write_report(tmp_path, "R", checkpoint=True)
    body = client.delete(
        "/api/v1/reports/R?include_checkpoint=true").get_json()

    assert "R.partial.json" in body["deleted"]
    assert "checkpoint_kept" not in body
    assert not (tmp_path / "R.partial.json").exists()
    listing = client.get("/api/v1/reports").get_json()
    assert listing["resumable_checkpoints"] == []


def test_delete_unknown_report_is_404(client):
    assert client.delete("/api/v1/reports/GHOST").status_code == 404


def test_delete_refuses_while_the_review_is_still_running(client, tmp_path,
                                                          monkeypatch):
    """Unlinking the report of an in-flight review would race the worker that
    is writing it."""
    gate = {"go": False}

    def slow(manifest, prompt, progress=None, mode="brief", **_):
        while not gate["go"]:
            time.sleep(0.02)
        return {"stats": {}, "reviews": [], "failures": [], "skipped": [],
                "mode": mode, "repo_url": "r", "commit": "c", "model": "m",
                "generated_at": "n"}

    monkeypatch.setattr(pipeline, "review_manifest", slow)
    _write_report(tmp_path, "LIVE-1")            # an earlier run's report
    client.post("/api/v1/reviews", json={
        "review_id": "LIVE-1", "repo_url": "https://github.com/o/r"})
    try:
        r = client.delete("/api/v1/reports/LIVE-1")
        assert r.status_code == 409
        body = r.get_json()
        assert body["status_of_review"] in ("requested", "cloning", "reviewing")
        assert "cancel" in body["hint"]
        assert (tmp_path / "LIVE-1.json").exists()   # nothing was removed
    finally:
        gate["go"] = True
        _wait(client, "LIVE-1")


@pytest.mark.parametrize("name", [
    "../outside",          # stopped by URL routing before the handler
    "%2e%2e%2foutside",    # ...and still stopped once decoded
    "..%2Foutside",
    "..\\outside",         # backslash IS a legal URL char: reaches the handler
    "..%5Coutside",        # and matters on Windows, where it separates paths
    "..", ".",             # rejected outright as unusable names
])
def test_a_report_name_cannot_reach_outside_the_reports_dir(client, tmp_path,
                                                            name):
    """Report names arrive in the URL, so containment is the whole game: a
    GET must not read, and a DELETE must not unlink, anything above the
    reports directory.

    Two layers do the work and the test deliberately covers both — URL
    routing rejects names containing `/`, and `_report_file` sanitises what
    routing lets through (a backslash becomes an underscore) before
    re-checking that the resolved path's parent is still the reports dir.
    """
    outside = tmp_path.parent / "outside.json"
    outside.write_text('{"secret": true}', encoding="utf-8")

    assert client.get(f"/api/v1/reports/{name}").status_code in (400, 404)
    assert client.delete(f"/api/v1/reports/{name}").status_code in (400, 404)
    assert outside.exists()
    assert json.loads(outside.read_text(encoding="utf-8")) == {"secret": True}


def test_a_separator_in_a_name_is_neutralised_not_followed(client, tmp_path):
    """The name that DOES reach the handler must be collapsed into a plain
    filename inside the reports dir — never followed as a path.

    `..\\R` becomes `_R.json` there, so it can only ever 404; proven by
    creating exactly that file and watching the request find it.
    """
    _write_report(tmp_path, "_R", markdown=False)
    body = client.get("/api/v1/reports/..%5CR").get_json()
    assert body["report"] == "_R.json"


def test_delete_requires_the_api_key_when_one_is_set(tmp_path, monkeypatch):
    """The destructive route sits behind the same gate as everything else."""
    from review_api.app import create_app

    cfg = _cfg(tmp_path)
    cfg.api_key = "s3cret"
    app = create_app(cfg=cfg)
    app.config.update(TESTING=True)
    c = app.test_client()
    _write_report(tmp_path, "R")

    assert c.delete("/api/v1/reports/R").status_code == 401
    assert (tmp_path / "R.json").exists()
    assert c.delete("/api/v1/reports/R",
                    headers={"X-API-Key": "s3cret"}).status_code == 200


# ---------------- sharing the API with teammates --------------------------

@pytest.mark.parametrize("host,loopback", [
    ("127.0.0.1", True), ("localhost", True), ("::1", True), ("", True),
    ("0.0.0.0", False), ("100.93.244.39", False),      # a tailnet address
    ("192.168.1.5", False), ("box.tail1234.ts.net", False),
])
def test_is_loopback_host(host, loopback):
    """Whether other machines can reach us decides whether startup warns.

    An unresolvable hostname counts as reachable: the safe assumption is the
    one that produces the warning.
    """
    from review_api.config import is_loopback_host
    assert is_loopback_host(host) is loopback


def test_cors_advertises_delete(client):
    """A browser preflights DELETE; omitting it from Allow-Methods blocks the
    call from any cross-origin client, including the demo console."""
    methods = client.get("/api/v1/reports").headers[
        "Access-Control-Allow-Methods"]
    assert "DELETE" in methods


# ---------------- retry-failed: top up a report that has gaps -------------

def _finished_report(dir_path, review_id, failures):
    """A completed report that still carries failed files."""
    reviews = [{"file": "ok.py", "summary": "fine", "score": 8, "issues": []}]
    (dir_path / f"{review_id}.json").write_text(json.dumps({
        "repo_url": "https://github.com/o/r", "branch": "", "commit": "abc",
        "mode": "deep", "model": "m", "generated_at": "now",
        "reviews": reviews,
        "failures": [{"file": f, "error": "Model failed to return valid JSON"}
                     for f in failures],
        "skipped": [], "excluded": {"count": 0},
        "stats": {"files_reviewed": 1, "files_failed": len(failures),
                  "files_skipped": 0, "issues_total": 0,
                  "issues_by_severity": {}, "average_score": 8},
    }), encoding="utf-8")


def test_retry_failed_reviews_only_the_failures_and_merges_them(
        client, tmp_path, monkeypatch):
    """A deep run ends with files reviewed, skipped, and FAILED — and the
    failures are a response-format problem, not a verdict on the code."""
    _finished_report(tmp_path, "GAPS-1", ["b.py", "c.py"])
    seen = {}

    def fake_run_review(repo_url, prompt, output_path, **kwargs):
        seen["files"] = sorted(kwargs.get("files") or [])
        (tmp_path / output_path).write_text("{}", encoding="utf-8")
        return {"generated_at": "now", "failures": [],
                "reviews": [{"file": "b.py", "issues": [], "score": 6},
                            {"file": "c.py", "issues": [], "score": 7}]}

    monkeypatch.setattr(pipeline, "run_review", fake_run_review)

    r = client.post("/api/v1/reviews/GAPS-1/retry-failed")
    assert r.status_code == 202
    assert r.get_json()["action"] == "retrying"
    assert r.get_json()["files_to_retry"] == 2
    _wait(client, "GAPS-1")

    assert seen["files"] == ["b.py", "c.py"]
    merged = json.loads((tmp_path / "GAPS-1.json").read_text(encoding="utf-8"))
    assert {x["file"] for x in merged["reviews"]} == {"ok.py", "b.py", "c.py"}
    assert merged["failures"] == []
    assert merged["stats"]["files_reviewed"] == 3


def test_retry_failed_is_idempotent_over_the_api(client, tmp_path, monkeypatch):
    _finished_report(tmp_path, "GAPS-2", ["b.py"])

    def fake_run_review(repo_url, prompt, output_path, **kwargs):
        (tmp_path / output_path).write_text("{}", encoding="utf-8")
        return {"generated_at": "now", "failures": [],
                "reviews": [{"file": "b.py", "issues": [], "score": 6}]}

    monkeypatch.setattr(pipeline, "run_review", fake_run_review)
    client.post("/api/v1/reviews/GAPS-2/retry-failed")
    _wait(client, "GAPS-2")

    # Second call: nothing left to retry, and that is a success not an error.
    second = client.post("/api/v1/reviews/GAPS-2/retry-failed")
    assert second.status_code == 200
    assert second.get_json()["action"] == "nothing_to_retry"
    merged = json.loads((tmp_path / "GAPS-2.json").read_text(encoding="utf-8"))
    assert len(merged["reviews"]) == 2          # not duplicated


def test_retry_failed_works_without_a_job_record(client, tmp_path, monkeypatch):
    """The registry is in memory, so a finished run loses its status when the
    API restarts while its report survives. That report is exactly what
    someone comes back to."""
    _finished_report(tmp_path, "ORPHAN-1", ["b.py"])
    monkeypatch.setattr(pipeline, "run_review",
                        lambda repo_url, prompt, output_path, **k: (
                            (tmp_path / output_path).write_text("{}", encoding="utf-8"),
                            {"generated_at": "now", "failures": [],
                             "reviews": [{"file": "b.py", "issues": [], "score": 5}]})[1])

    # No job record: the status now comes from the report on disk.
    orphan = client.get("/api/v1/reviews/ORPHAN-1").get_json()
    assert (orphan["status"], orphan["source"]) == ("completed", "disk")
    r = client.post("/api/v1/reviews/ORPHAN-1/retry-failed")
    assert r.status_code == 202
    _wait(client, "ORPHAN-1")
    merged = json.loads((tmp_path / "ORPHAN-1.json").read_text(encoding="utf-8"))
    assert merged["stats"]["files_failed"] == 0


def test_retry_failed_without_a_report_is_404(client):
    r = client.post("/api/v1/reviews/NEVER-RAN/retry-failed")
    assert r.status_code == 404
    assert "retry-failed tops up" in r.get_json()["hint"]


def test_retry_failed_cannot_escape_the_reports_directory(client, tmp_path):
    outside = tmp_path.parent / "outside.json"
    outside.write_text('{"secret": true}', encoding="utf-8")
    assert client.post("/api/v1/reviews/../outside/retry-failed").status_code         in (400, 404, 405)
    assert outside.exists()


# ---------------- per-file progress view ----------------
#
# The endpoint reads its answer off disk (plan + checkpoint + report) rather
# than out of the job registry, so these tests write those files directly:
# that is exactly the state a real review leaves behind mid-run, and it is
# also the state the endpoint must still answer from after a restart.

def _plan(tmp_path, review_id, paths, mode="deep"):
    (tmp_path / f"{review_id}.plan.json").write_text(json.dumps({
        "plan_version": 1, "repo_url": "https://github.com/o/r",
        "commit": "abc1234", "mode": mode,
        "files": [{"path": p, "language": "python"} for p in paths],
    }), encoding="utf-8")


def _checkpoint(tmp_path, review_id, reviews=(), failures=(), mode="deep"):
    (tmp_path / f"{review_id}.partial.json").write_text(json.dumps({
        "checkpoint_version": 1, "repo_url": "https://github.com/o/r",
        "commit": "abc1234", "mode": mode,
        "reviews": list(reviews), "failures": list(failures),
    }), encoding="utf-8")


def test_file_view_separates_done_failed_and_pending(client, tmp_path):
    _plan(tmp_path, "R1", ["a.py", "b.py", "c.py", "d.py"])
    _checkpoint(
        tmp_path, "R1",
        reviews=[{"file": "a.py", "score": 8, "issues": [{"title": "x"}]}],
        failures=[{"file": "b.py", "error": "model returned no JSON"}])

    body = client.get("/api/v1/reviews/R1/files").get_json()

    states = {f["path"]: f["state"] for f in body["files"]}
    assert states == {"a.py": "done", "b.py": "failed",
                      "c.py": "pending", "d.py": "pending"}
    assert body["counts"] == {"total": 4, "done": 1, "failed": 1,
                              "in_progress": 0, "pending": 2}
    assert body["source"] == "plan"


def test_file_view_keeps_the_plan_order(client, tmp_path):
    ordered = ["z.py", "m.py", "a.py"]
    _plan(tmp_path, "R2", ordered)
    assert [f["path"] for f in
            client.get("/api/v1/reviews/R2/files").get_json()["files"]] \
        == ordered


def test_file_view_reports_counts_not_issue_text(client, tmp_path):
    """The whole point of a separate endpoint: it is polled constantly, so it
    carries progress only. Issue detail stays in the report endpoint."""
    _plan(tmp_path, "R3", ["a.py"])
    _checkpoint(tmp_path, "R3", reviews=[{
        "file": "a.py", "score": 4,
        "summary": "SECRET-LOOKING SUMMARY TEXT",
        "issues": [{"title": "Hardcoded password",
                    "description": "the literal password is hunter2"}]}])

    response = client.get("/api/v1/reviews/R3/files")
    entry = response.get_json()["files"][0]

    assert entry["issues"] == 1 and entry["score"] == 4
    raw = response.get_data(as_text=True)
    assert "hunter2" not in raw
    assert "Hardcoded password" not in raw
    assert "SECRET-LOOKING SUMMARY TEXT" not in raw


def test_file_view_falls_back_to_the_finished_report(client, tmp_path):
    """Plan and checkpoint are deleted when a review completes; the finished
    report still has to be able to answer the same question."""
    (tmp_path / "R4.json").write_text(json.dumps({
        "repo_url": "https://github.com/o/r", "commit": "abc1234",
        "mode": "deep",
        "reviews": [{"file": "a.py", "score": 9, "issues": []}],
        "failures": [{"file": "b.py", "error": "connection dropped"}],
    }), encoding="utf-8")

    body = client.get("/api/v1/reviews/R4/files").get_json()

    assert body["source"] == "report"
    assert {f["path"]: f["state"] for f in body["files"]} == {
        "a.py": "done", "b.py": "failed"}


def test_file_view_404s_before_anything_is_on_disk(client):
    response = client.get("/api/v1/reviews/nothing-yet/files")
    assert response.status_code == 404
    # A 404 here is normal early in a review, so it must say so rather than
    # read as "this review does not exist".
    assert "plan" in response.get_json()["hint"].lower()


def test_file_view_cannot_be_walked_out_of_the_reports_directory(
        client, tmp_path):
    """Review ids name files, so the id is sanitized before it touches a
    path — the same protection the report endpoints rely on."""
    (tmp_path.parent / "outside.json").write_text(
        json.dumps({"reviews": [{"file": "leaked.py"}]}), encoding="utf-8")
    assert client.get(
        "/api/v1/reviews/..%2Foutside/files").status_code in (404, 308)


def _live_job(client, review_id, *messages):
    """A review the in-memory registry believes is mid-run.

    The messages go through the store's real progress handler, in order,
    exactly as the engine would send them - so these tests exercise the
    same parsing a live review does, not fields set by hand.
    """
    from review_api.jobs import Job

    store = client.application.config["JOB_STORE"]
    job = Job(job_id=f"job-{review_id}", review_id=review_id,
              repo_url="https://github.com/o/r", mode="deep",
              provider="onprem", model="local-model")
    job.status = "reviewing"
    store._jobs[job.job_id] = job
    store._by_review_id[review_id] = job.job_id
    for message in messages:
        store._on_progress(job, 0, None, message, None)
    return job


def test_file_view_marks_the_file_being_reviewed(client, tmp_path):
    """Joins the status message to the plan: "<path>: <anything>" names the
    file in flight. This join had no test, which is how a status format
    that never named the running file went unnoticed."""
    _plan(tmp_path, "R5", ["a.py", "b.py", "c.py"])
    _checkpoint(tmp_path, "R5",
                reviews=[{"file": "a.py", "score": 8, "issues": []}])
    _live_job(client, "R5", "b.py: reviewing")

    states = {f["path"]: f["state"] for f in
              client.get("/api/v1/reviews/R5/files").get_json()["files"]}
    assert states == {"a.py": "done", "b.py": "in_progress",
                      "c.py": "pending"}


def test_file_view_guesses_nothing_between_files(client, tmp_path):
    """Between files the message names the one that just finished. That
    file is done, so nothing is marked running - an honest gap rather than
    a guess about which file comes next."""
    _plan(tmp_path, "R6", ["a.py", "b.py"])
    _checkpoint(tmp_path, "R6",
                reviews=[{"file": "a.py", "score": 8, "issues": []}])
    _live_job(client, "R6", "a.py done (1/2)")

    body = client.get("/api/v1/reviews/R6/files").get_json()
    assert body["counts"]["in_progress"] == 0
    assert {f["path"]: f["state"] for f in body["files"]} == {
        "a.py": "done", "b.py": "pending"}


# ---------------- progress view: live timing and scanner status ----------------

def _plan_sized(tmp_path, review_id, sizes):
    (tmp_path / f"{review_id}.plan.json").write_text(json.dumps({
        "plan_version": 1, "repo_url": "https://github.com/o/r",
        "commit": "abc1234", "mode": "deep",
        "files": [{"path": p, "language": "python", "size": n}
                  for p, n in sizes.items()],
    }), encoding="utf-8")


def test_the_store_tracks_the_running_file_from_progress_messages():
    from review_api.jobs import Job, JobStore

    store = JobStore(_cfg_for_store())
    job = Job(job_id="j", review_id="r", repo_url="u", mode="deep",
              provider="p", model="m")
    for message in ("a.py: reviewing", "a.py: thinking (40 tokens streamed)",
                    "a.py done (1/2)", "b.py: reviewing"):
        store._on_progress(job, 0, None, message, None)

    assert job.current_file == "b.py"
    assert [path for path, _ in job.durations] == ["a.py"]
    assert set(job.file_started) == {"b.py"}  # a.py left when it finished

    # A heartbeat for the SAME file must not restart its clock.
    first_start = job.file_started["b.py"]
    store._on_progress(job, 1, None, "b.py: thinking (9 tokens streamed)", None)
    assert job.file_started["b.py"] == first_start


def test_a_status_line_that_merely_contains_a_colon_is_not_a_file():
    from review_api.jobs import Job, JobStore

    store = JobStore(_cfg_for_store())
    job = Job(job_id="j", review_id="r", repo_url="u", mode="deep",
              provider="p", model="m")
    store._on_progress(job, 0, None, "error: something odd", None)
    assert job.current_file == "" and job.file_started == {}


def _cfg_for_store():
    from review_api.config import ApiConfig
    return ApiConfig()


def _timed_job(client, review_id, durations, running=None, running_for=0):
    """A live review with measured per-file durations, and optionally a file
    that has been running for `running_for` seconds."""
    job = _live_job(client, review_id,
                    *([f"{running}: reviewing"] if running else []))
    job.durations = list(durations)
    if running:
        job.current_file_started = time.monotonic() - running_for
    return job


def test_one_measured_file_predicts_the_next_takes_about_as_long(
        client, tmp_path):
    """With a single measurement there is no evidence about size at all, so
    the honest prediction is "about as long as the last one"."""
    _plan_sized(tmp_path, "T1", {"a.py": 1000, "b.py": 500, "c.py": 2000})
    _checkpoint(tmp_path, "T1",
                reviews=[{"file": "a.py", "score": 8, "issues": []}])
    _timed_job(client, "T1", [("a.py", 10.0)], running="b.py", running_for=2)

    body = client.get("/api/v1/reviews/T1/files").get_json()

    assert body["current"] == {"path": "b.py", "elapsed_seconds": 2,
                               "expected_seconds": 10}
    assert body["eta_seconds"] == 18  # c.py ~10s, plus ~8s left on b.py


def test_size_counts_once_bigger_files_are_measurably_slower(client, tmp_path):
    """1000 chars took 10s and 3000 took 30s: the measurements show time
    scaling with size, so a 2000-char file is predicted at ~20s."""
    _plan_sized(tmp_path, "T2", {"a.py": 1000, "b.py": 3000, "c.py": 2000})
    _checkpoint(tmp_path, "T2", reviews=[
        {"file": "a.py", "score": 8, "issues": []},
        {"file": "b.py", "score": 8, "issues": []}])
    _timed_job(client, "T2", [("a.py", 10.0), ("b.py", 30.0)])

    assert client.get("/api/v1/reviews/T2/files").get_json()["eta_seconds"] == 20


def test_small_files_first_do_not_inflate_the_eta(client, tmp_path):
    """The bug this model replaced, measured live on 2026-09-25: a 5-minute
    review showed 69 minutes left. Small files finished first, every file
    took the same ~2s whatever its size, and a pure seconds-per-character
    rate learned from tiny files was multiplied by the big ones left.

    Here: three files of very different sizes all took 2s, so size explains
    nothing - ten more files are ~20s, not the ~230s the old rate gave."""
    sizes = {"a.py": 100, "b.py": 150, "c.py": 5000}
    sizes.update({f"big{i}.py": 20000 for i in range(10)})
    _plan_sized(tmp_path, "T3", sizes)
    _checkpoint(tmp_path, "T3", reviews=[
        {"file": p, "score": 8, "issues": []} for p in ("a.py", "b.py", "c.py")])
    _timed_job(client, "T3", [("a.py", 2.0), ("b.py", 2.0), ("c.py", 2.0)])

    assert client.get("/api/v1/reviews/T3/files").get_json()["eta_seconds"] == 20


def test_eta_stays_accurate_after_resuming_from_a_checkpoint(client, tmp_path):
    """After a resume, the checkpoint lists files this run never worked on:
    they were restored, and took no time here. Only files that finished in
    THIS run may feed the estimate.

    old.py is restored (in the checkpoint, never started in this run).
    a.py took 10s in this run. b.py is left, so ~10s. Had old.py been taken
    as a file that finished in 0s, the average would halve to ~5s - an ETA
    that is wrong in the optimistic direction, the one that misleads."""
    _plan_sized(tmp_path, "T4", {"old.py": 1000, "a.py": 1000, "b.py": 1000})
    _checkpoint(tmp_path, "T4", reviews=[
        {"file": "old.py", "score": 8, "issues": []},   # restored
        {"file": "a.py", "score": 8, "issues": []}])     # this run
    _timed_job(client, "T4", [("a.py", 10.0)])

    assert client.get("/api/v1/reviews/T4/files").get_json()["eta_seconds"] == 10


def test_eta_accounts_for_files_reviewed_in_parallel(client, tmp_path,
                                                     monkeypatch):
    from code_review_mcp.config import settings

    monkeypatch.setattr(settings, "parallel", 2)
    _plan_sized(tmp_path, "T5", {p: 1000 for p in ("a.py", "b.py", "c.py",
                                                   "d.py")})
    _checkpoint(tmp_path, "T5",
                reviews=[{"file": "a.py", "score": 8, "issues": []}])
    _timed_job(client, "T5", [("a.py", 10.0)])

    # Three files of ~10s each, two at a time.
    assert client.get("/api/v1/reviews/T5/files").get_json()["eta_seconds"] == 15


def test_no_estimate_until_a_file_has_finished_in_this_run(client, tmp_path):
    _plan_sized(tmp_path, "T6", {"a.py": 1000, "b.py": 1000})
    _live_job(client, "T6", "a.py: reviewing")

    body = client.get("/api/v1/reviews/T6/files").get_json()

    assert body["current"]["path"] == "a.py"
    assert body["current"]["expected_seconds"] is None
    assert body["eta_seconds"] is None


def test_scanner_status_reports_each_scanner(client, tmp_path):
    """A scanner that failed silently otherwise looks like a clean result."""
    _plan_sized(tmp_path, "S1", {"a.py": 10})
    (tmp_path / "S1.findings.json").write_text(json.dumps({
        "source": "semgrep+gitleaks", "findings": [],
        "scanners_run": ["gitleaks", "semgrep"],
        "scanners_failed": {"trivy": "timed out after 300s"},
        "coverage": {"semgrep": {"scanned_files": 98, "errors": 2},
                     "gitleaks": {"scanned_files": None, "errors": 0}},
    }), encoding="utf-8")

    scanners = client.get("/api/v1/reviews/S1/files").get_json()["scanners"]

    assert scanners["run"] == ["gitleaks", "semgrep"]
    assert scanners["failed"] == {"trivy": "timed out after 300s"}
    assert scanners["coverage"]["semgrep"]["errors"] == 2


def test_no_findings_file_is_reported_as_unknown_not_as_clean(client, tmp_path):
    _plan_sized(tmp_path, "S2", {"a.py": 10})
    assert client.get("/api/v1/reviews/S2/files").get_json()["scanners"] is None


def test_estimate_says_how_many_files_it_rests_on(client, tmp_path):
    """"About 3 hours" from 2 measured files is a rough guess; from 40 it is
    much less so. The count lets the page say which."""
    _plan_sized(tmp_path, "T7", {"a.py": 1000, "b.py": 1000, "c.py": 1000})
    _checkpoint(tmp_path, "T7", reviews=[
        {"file": "a.py", "score": 8, "issues": []},
        {"file": "b.py", "score": 8, "issues": []}])
    _timed_job(client, "T7", [("a.py", 10.0), ("b.py", 12.0)])

    assert client.get("/api/v1/reviews/T7/files").get_json()[
        "estimate_based_on"] == 2


def test_file_view_passes_line_counts_through_for_people(client, tmp_path):
    (tmp_path / "L1.plan.json").write_text(json.dumps({
        "plan_version": 1, "repo_url": "https://github.com/o/r",
        "commit": "abc1234", "mode": "deep",
        "files": [{"path": "a.py", "language": "python", "size": 900,
                   "lines": 34}],
    }), encoding="utf-8")

    entry = client.get("/api/v1/reviews/L1/files").get_json()["files"][0]
    assert entry["lines"] == 34 and entry["size"] == 900


def test_scanner_findings_are_counted_per_scanner_not_hidden(client, tmp_path):
    """Scanner findings sit under `static_findings`, beside the model's
    `issues`. Counting only `issues` showed a file holding three Gitleaks
    secrets as "1 finding" - in a security tool, the undercount that
    matters most."""
    _plan(tmp_path, "F1", ["a.py"])
    _checkpoint(tmp_path, "F1", reviews=[{
        "file": "a.py", "score": 4,
        "issues": [{"title": "model issue"}],
        "static_findings": [
            {"source": "gitleaks", "rule": "aws-key",
             "description": "AKIA-LOOKING SECRET VALUE"},
            {"source": "gitleaks", "rule": "generic-api-key"},
            {"source": "semgrep", "rule": "python.lang.eval"},
        ]}])

    response = client.get("/api/v1/reviews/F1/files")
    entry = response.get_json()["files"][0]

    assert entry["issues"] == 1
    assert entry["scanner_findings"] == {"gitleaks": 2, "semgrep": 1}
    # Counts only: no finding text travels through this endpoint.
    assert "AKIA-LOOKING SECRET VALUE" not in response.get_data(as_text=True)


# ---------------- the plan outlives the review ----------------

def _report_on_disk(tmp_path, review_id, reviews):
    (tmp_path / f"{review_id}.json").write_text(json.dumps({
        "repo_url": "https://github.com/o/r", "commit": "abc1234",
        "mode": "deep", "stats": {"files_reviewed": len(reviews)},
        "reviews": reviews, "failures": [],
    }), encoding="utf-8")


def test_a_finished_review_keeps_its_line_counts(client, tmp_path):
    """Once a review ends its checkpoint is gone, and the report carries no
    sizes. The kept plan supplies them, and the report supplies the states -
    so the view people look at most, a finished one, still shows both."""
    (tmp_path / "P1.plan.json").write_text(json.dumps({
        "plan_version": 1, "repo_url": "https://github.com/o/r",
        "commit": "abc1234", "mode": "deep",
        "files": [{"path": "a.py", "language": "python", "size": 900,
                   "lines": 34},
                  {"path": "b.py", "language": "python", "size": 90,
                   "lines": 5}],
    }), encoding="utf-8")
    _report_on_disk(tmp_path, "P1", [
        {"file": "a.py", "score": 8, "issues": []},
        {"file": "b.py", "score": 9, "issues": []}])

    files = client.get("/api/v1/reviews/P1/files").get_json()["files"]

    assert [(f["path"], f["state"], f["lines"]) for f in files] == [
        ("a.py", "done", 34), ("b.py", "done", 5)]


def test_a_rerun_does_not_show_the_previous_runs_files_as_done(client,
                                                              tmp_path):
    """Same review id run again: until the new run writes a checkpoint, the
    report on disk belongs to the PREVIOUS run. Reading it would mark files
    done that this run has not touched."""
    _plan(tmp_path, "P2", ["a.py", "b.py"])
    _report_on_disk(tmp_path, "P2", [
        {"file": "a.py", "score": 8, "issues": []},
        {"file": "b.py", "score": 8, "issues": []}])
    _live_job(client, "P2", "a.py: reviewing")

    states = {f["path"]: f["state"] for f in
              client.get("/api/v1/reviews/P2/files").get_json()["files"]}

    assert states == {"a.py": "in_progress", "b.py": "pending"}


def test_review_sidecars_are_not_listed_as_reports(client, tmp_path):
    """The plan carries repo_url, so it used to be listed as a report while
    a review ran. The worker's error and progress files are excluded ahead
    of time, before they exist."""
    _report_on_disk(tmp_path, "R9", [{"file": "a.py", "score": 8,
                                       "issues": []}])
    for suffix in ("plan", "error", "progress", "partial"):
        (tmp_path / f"R9.{suffix}.json").write_text(
            json.dumps({"repo_url": "https://github.com/o/r"}),
            encoding="utf-8")

    names = [r["name"] for r in
             client.get("/api/v1/reports").get_json()["reports"]]

    assert names == ["R9.json"]


def test_deleting_a_report_deletes_its_plan(client, tmp_path):
    """Kept for its sizes, and meaningless without the report."""
    _report_on_disk(tmp_path, "D9", [{"file": "a.py", "score": 8,
                                       "issues": []}])
    _plan(tmp_path, "D9", ["a.py"])

    assert client.delete("/api/v1/reports/D9").status_code == 200
    assert not (tmp_path / "D9.plan.json").exists()


# ---------------- "no findings" is only claimed when every check ran ----------------

def _scan_file(tmp_path, review_id, failed=None, error_files=None,
               truncated=0):
    semgrep = {"scanned_files": 3, "errors": len(error_files or []),
               "error_files": list(error_files or [])}
    if truncated:
        semgrep["error_files_truncated"] = truncated
    (tmp_path / f"{review_id}.findings.json").write_text(json.dumps({
        "source": "semgrep", "findings": [],
        "scanners_run": ["gitleaks", "semgrep", "trivy"],
        "scanners_failed": dict(failed or {}),
        "coverage": {"semgrep": semgrep},
    }), encoding="utf-8")


def _gaps(client, review_id):
    return {f["path"]: f["scan_gaps"] for f in
            client.get(f"/api/v1/reviews/{review_id}/files").get_json()["files"]
            if f["state"] == "done"}


def _two_clean_files(tmp_path, review_id):
    _plan(tmp_path, review_id, ["a.py", "b.py"])
    _checkpoint(tmp_path, review_id, reviews=[
        {"file": "a.py", "score": 9, "issues": []},
        {"file": "b.py", "score": 9, "issues": []}])


def test_no_gaps_when_every_scanner_ran_and_parsed_the_file(client, tmp_path):
    _two_clean_files(tmp_path, "G1")
    _scan_file(tmp_path, "G1")
    assert _gaps(client, "G1") == {"a.py": [], "b.py": []}


def test_a_file_semgrep_only_partly_parsed_is_not_fully_checked(client,
                                                                tmp_path):
    """Semgrep lists a partly-parsed file as scanned; without this it would
    read "no findings" exactly like a file it read in full."""
    _two_clean_files(tmp_path, "G2")
    _scan_file(tmp_path, "G2", error_files=["b.py"])
    assert _gaps(client, "G2") == {
        "a.py": [], "b.py": ["semgrep could only partly parse it"]}


def test_a_failed_scanner_leaves_every_file_incomplete(client, tmp_path):
    _two_clean_files(tmp_path, "G3")
    _scan_file(tmp_path, "G3", failed={"trivy": "timed out after 300s"})
    assert _gaps(client, "G3") == {"a.py": ["trivy failed"],
                                   "b.py": ["trivy failed"]}


def test_unlisted_semgrep_errors_leave_every_file_incomplete(client, tmp_path):
    """If some errored files went unnamed, any file might be one of them."""
    _two_clean_files(tmp_path, "G4")
    _scan_file(tmp_path, "G4", error_files=["b.py"], truncated=40)
    gaps = _gaps(client, "G4")
    assert gaps["a.py"] == ["semgrep errors not all listed"]
    assert "semgrep could only partly parse it" in gaps["b.py"]


def test_no_scanner_results_means_no_file_was_scanner_checked(client,
                                                             tmp_path):
    _two_clean_files(tmp_path, "G5")
    assert _gaps(client, "G5") == {
        "a.py": ["no scanner results were recorded"],
        "b.py": ["no scanner results were recorded"]}


# ---------------- the AI service from Settings ----------------

def test_presets_are_listed_with_fixed_addresses(client):
    body = client.get("/api/v1/llm/presets").get_json()
    names = {p["name"]: p for p in body["presets"]}
    assert names["openai"]["base_url"] == "https://api.openai.com/v1"
    assert names["local"]["base_url"] is None
    assert body["server_default"]["provider"] == "onprem"


def test_a_cloud_service_without_a_key_is_refused(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "AI-0", "repo_url": "https://github.com/o/r",
        "llm": {"preset": "openai", "model": "gpt-x"}})
    assert r.status_code == 400
    assert "API key" in r.get_json()["detail"]


def test_a_cloud_service_cannot_be_given_an_address(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "AI-2", "repo_url": "https://github.com/o/r",
        "llm": {"preset": "openai", "api_key": "sk-1",
                "endpoint": "http://evil.example"}})
    assert r.status_code == 400


def test_an_unknown_service_is_refused(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "AI-3", "repo_url": "https://github.com/o/r",
        "llm": {"preset": "nope"}})
    assert r.status_code == 400


def test_the_chosen_service_runs_the_review_and_its_key_never_shows(
        client, monkeypatch):
    seen = {}
    real = pipeline.review_manifest

    def spy(*a, **k):
        seen["base_url"] = settings.lm_base_url
        seen["api_key"] = settings.lm_api_key
        seen["model"] = settings.lm_model
        return real(*a, **k)

    monkeypatch.setattr(pipeline, "review_manifest", spy)
    r = client.post("/api/v1/reviews", json={
        "review_id": "AI-1", "repo_url": "https://github.com/o/r",
        "llm": {"preset": "openai", "model": "gpt-x",
                "api_key": "sk-live-abcdef"}})
    assert r.status_code == 202, r.get_json()
    done = _wait(client, "AI-1")
    assert done["status"] == "completed"
    assert seen == {"base_url": "https://api.openai.com/v1",
                    "api_key": "sk-live-abcdef", "model": "gpt-x"}
    assert done["ai_service"] == "openai"
    assert "sk-live-abcdef" not in json.dumps(done)
    assert "sk-live-abcdef" not in json.dumps(r.get_json())


def test_the_local_service_takes_a_private_address_only(client):
    r = client.post("/api/v1/reviews", json={
        "review_id": "AI-4", "repo_url": "https://github.com/o/r",
        "llm": {"preset": "local", "endpoint": "8.8.8.8"}})
    assert r.status_code == 400


def test_testing_a_service_hides_the_key_in_errors(client, monkeypatch):
    from review_api import app as app_mod

    def boom():
        raise RuntimeError("401 bad key sk-live-zzz for you")

    monkeypatch.setattr(app_mod.llm, "make_client", boom)
    r = client.post("/api/v1/llm/models", json={
        "llm": {"preset": "openai", "api_key": "sk-live-zzz"}})
    body = r.get_json()
    assert r.status_code == 200 and body["reachable"] is False
    assert "sk-live-zzz" not in json.dumps(body)


def test_testing_a_service_lists_its_models(client, monkeypatch):
    from types import SimpleNamespace

    from review_api import app as app_mod
    fake = SimpleNamespace(models=SimpleNamespace(list=lambda: SimpleNamespace(
        data=[SimpleNamespace(id="b"), SimpleNamespace(id="a")])))
    monkeypatch.setattr(app_mod.llm, "make_client", lambda: fake)
    body = client.post("/api/v1/llm/models", json={
        "llm": {"preset": "groq", "api_key": "gsk"}}).get_json()
    assert body["reachable"] and body["models"] == ["a", "b"]


# ---------------- deleting a review ----------------

def test_delete_removes_every_file_of_the_review_and_nothing_else(
        client, tmp_path):
    client.post("/api/v1/reviews", json={
        "review_id": "D-1", "repo_url": "https://github.com/o/r"})
    _wait(client, "D-1")
    for suffix in (".partial.json", ".findings.json", ".paused.json"):
        (tmp_path / f"D-1{suffix}").write_text("{}", encoding="utf-8")
    (tmp_path / "D-10.json").write_text("{}", encoding="utf-8")   # a neighbour
    r = client.delete("/api/v1/reviews/D-1")
    assert r.status_code == 200, r.get_json()
    assert "D-1.json" in r.get_json()["removed"]
    assert not list(tmp_path.glob("D-1.*"))
    assert (tmp_path / "D-10.json").is_file()
    assert client.get("/api/v1/reviews/D-1").status_code == 404


def test_delete_of_a_running_review_is_refused(client, tmp_path):
    store = client.application.config["JOB_STORE"]
    from review_api.jobs import Job
    job = Job(job_id="j", review_id="D-2", repo_url="https://github.com/o/r",
              mode="brief", provider="onprem", model="m", status="reviewing")
    store._jobs["j"] = job
    store._by_review_id["D-2"] = "j"
    assert client.delete("/api/v1/reviews/D-2").status_code == 409


def test_delete_of_nothing_is_404_and_bad_ids_are_400(client):
    assert client.delete("/api/v1/reviews/NOPE").status_code == 404
    assert client.delete("/api/v1/reviews/..%2Fx").status_code in (400, 404)


def test_the_key_may_come_in_the_x_llm_key_header(client, monkeypatch):
    seen = {}
    real = pipeline.review_manifest

    def spy(*a, **k):
        seen["api_key"] = settings.lm_api_key
        return real(*a, **k)

    monkeypatch.setattr(pipeline, "review_manifest", spy)
    r = client.post("/api/v1/reviews", headers={"X-LLM-Key": "sk-hdr-1"},
                    json={"review_id": "AI-H", "repo_url": "https://github.com/o/r",
                          "llm": {"preset": "openai"}})
    assert r.status_code == 202, r.get_json()
    _wait(client, "AI-H")
    assert seen["api_key"] == "sk-hdr-1"
