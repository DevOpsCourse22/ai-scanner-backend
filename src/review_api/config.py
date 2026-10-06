"""Configuration for the review API (requirement 6).

Everything the API needs is declared in ONE file — `config/api.yaml` by
default — and every value can be overridden by an environment variable so
the same file works in dev, Docker, and CI.

The central concept is the **provider**: a named LLM endpoint. Providers are
how the API points at either an on-prem model (LM Studio, Ollama, vLLM) or a
cloud one (OpenAI, Azure, Groq, ...) without code changes; a request just
names the provider it wants.

API KEYS ARE NEVER STORED IN THIS FILE. A provider declares `api_key_env`,
the NAME of an environment variable, and the key is read from the process
environment at call time. That keeps the config file safe to commit and
share.

PORTABILITY. The same committed file has to work on every teammate's
workstation, so two rules keep machine-specific values out of it:

* Any string may contain `${VAR}` or `${VAR:-fallback}`, expanded from the
  environment when the file is read. That is how one `base_url` line serves
  a laptop, a container (where the host is `host.docker.internal`) and CI.
* Relative paths resolve against the CONFIG FILE's directory, not the
  current working directory, so `python -m review_api.app` behaves the same
  whether you launch it from the repository root or from `backend/`.
"""

from __future__ import annotations

import json
import os
import re
import socket
import warnings
from collections.abc import Sequence
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_CONFIG_PATH = "config/api.yaml"

# Settings that no longer exist, and why. Present in older copies of the
# example config; ignored rather than rejected.
_RETIRED_KEYS = {
    "frontend_dir": "the test console is a separate service "
                    "(review-console); this API serves no UI",
}

# Search order for the config file when REVIEW_API_CONFIG is unset. Both the
# repository root and the backend/ folder are tried so neither launch
# directory is "the wrong one".
_CANDIDATES = (
    "config/api.yaml", "config/api.yml", "config/api.json",
    "backend/config/api.yaml", "backend/config/api.yml",
    "backend/config/api.json",
)

# ${VAR} or ${VAR:-fallback}
_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(RuntimeError):
    """Raised when the configuration file is missing or invalid."""


class EndpointError(ValueError):
    """Raised when a caller-supplied LLM endpoint is unusable or not allowed."""


# Networks a caller-supplied endpoint may point at, by default. The feature
# exists so a teammate can type the address of a machine running LM Studio on
# the team's Tailscale network, so the default is "addresses that belong to a
# private network you are already on":
#
#   127.0.0.0/8, ::1   loopback
#   10/8, 172.16/12, 192.168/16, fd00::/8   private (RFC 1918 / ULA)
#   100.64.0.0/10      CGNAT — this is the Tailscale range
#
# LINK-LOCAL IS DELIBERATELY EXCLUDED: 169.254.169.254 is the cloud instance
# metadata endpoint, and letting a request body steer the server at it is the
# textbook SSRF credential theft.
DEFAULT_ENDPOINT_NETWORKS = (
    "127.0.0.0/8", "::1/128",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8",
    "100.64.0.0/10",
)

_LMSTUDIO_DEFAULT_PORT = 1234


def is_loopback_host(host: str) -> bool:
    """True when binding to `host` keeps the API on this machine only.

    Anything else — a tailnet address, a LAN address, 0.0.0.0 — means other
    machines can reach an endpoint that clones repositories, accepts tokens
    and deletes reports, which is worth saying out loud at startup.
    """
    h = (host or "").strip().strip("[]").lower()
    if h in ("localhost", ""):
        return True
    try:
        return ip_address(h).is_loopback
    except ValueError:
        # A hostname we cannot resolve here: assume it is reachable, because
        # the safe assumption is the one that produces the warning.
        return False


@dataclass
class Provider:
    """One LLM endpoint the API can send reviews to."""

    name: str
    base_url: str
    # OpenAI-compatible covers LM Studio / Ollama / vLLM / OpenAI / Groq /
    # Together / Azure-compatible deployments — one client, many backends.
    kind: str = "openai_compatible"
    # NAME of the env var holding the key (never the key itself).
    api_key_env: str = ""
    # Fallback key for local servers that ignore auth (LM Studio: "lm-studio").
    api_key_default: str = "not-needed"
    default_model: str = ""
    # "on_prem" | "cloud" — advisory, surfaced to the UI so an operator can
    # see at a glance whether code would leave the premises.
    location: str = "on_prem"
    description: str = ""
    # What a human has to do to make this endpoint work, shown in
    # /api/v1/providers and in a failed probe. For endpoints that need a
    # per-workstation value (a teammate's Tailscale address, for instance) the
    # error is otherwise just a timeout, which teaches nobody anything.
    setup_hint: str = ""
    # Per-provider tuning; falls back to the review defaults when unset.
    max_tokens: int | None = None
    temperature: float | None = None
    parallel: int | None = None

    def __post_init__(self) -> None:
        # YAML folded scalars (`setup_hint: >`) keep a trailing newline and
        # the author's line breaks. These strings are shown to people in the
        # console and in probe errors, so collapse them to one clean line.
        self.setup_hint = " ".join(self.setup_hint.split())
        self.description = " ".join(self.description.split())

    @property
    def api_key(self) -> str:
        """Resolve the key from the environment at call time."""
        if self.api_key_env:
            return os.getenv(self.api_key_env, "") or self.api_key_default
        return self.api_key_default

    @property
    def key_present(self) -> bool:
        """Whether a key is actually available (for health reporting)."""
        return bool(not self.api_key_env or os.getenv(self.api_key_env))

    def public(self) -> dict[str, Any]:
        """Provider description safe to expose over HTTP (no secrets)."""
        return {
            "name": self.name,
            "kind": self.kind,
            "location": self.location,
            "base_url": self.base_url,
            "default_model": self.default_model,
            "description": self.description,
            "setup_hint": self.setup_hint or None,
            "api_key_env": self.api_key_env or None,
            "api_key_configured": self.key_present,
        }


@dataclass
class ApiConfig:
    """Effective API configuration."""

    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False
    # Where reports/checkpoints/findings files live (shared with the MCP).
    output_dir: str = "reports"
    default_provider: str = ""
    providers: dict[str, Provider] = field(default_factory=dict)
    default_mode: str = "brief"
    # Named reviewer personas, so a caller can ask for "security" instead of
    # pasting a system prompt every time.
    personas: dict[str, str] = field(default_factory=dict)
    default_persona: str = "general"
    # Optional shared secret required in the X-API-Key header. Empty = open
    # (fine on localhost; set it before exposing the API on a network).
    api_key: str = ""
    # Browser origins allowed to call the API (the demo UI). "*" for any.
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    # Server-wide fallback token for private clones when a request omits one.
    github_token_env: str = "GITHUB_TOKEN"
    # May a request name its own LLM endpoint (the "endpoint address" box in
    # the console)? Set false to allow only the configured providers.
    allow_custom_endpoint: bool = True
    # Networks such an endpoint may resolve into. See
    # DEFAULT_ENDPOINT_NETWORKS for why link-local is not among them.
    custom_endpoint_networks: list[str] = field(
        default_factory=lambda: list(DEFAULT_ENDPOINT_NETWORKS))
    review_defaults: dict[str, Any] = field(default_factory=dict)
    config_path: str = ""

    def provider(self, name: str | None = None) -> Provider:
        key = (name or self.default_provider or "").strip()
        if not key:
            raise ConfigError("No provider requested and no default_provider "
                              "is configured.")
        if key not in self.providers:
            raise ConfigError(
                f"Unknown provider {key!r}. Configured: "
                f"{', '.join(sorted(self.providers)) or '(none)'}"
            )
        return self.providers[key]

    def persona_prompt(self, name: str | None = None) -> tuple[str, str]:
        """Return (persona_name, system_prompt) for a named persona."""
        key = (name or self.default_persona or "").strip()
        if key and key in self.personas:
            return key, self.personas[key]
        if not self.personas:
            return "inline", ""
        raise ConfigError(
            f"Unknown persona {key!r}. Configured: "
            f"{', '.join(sorted(self.personas))}"
        )

    def public(self) -> dict[str, Any]:
        """The whole effective config, minus every secret."""
        return {
            "config_path": self.config_path,
            "host": self.host,
            "port": self.port,
            "output_dir": self.output_dir,
            "default_mode": self.default_mode,
            "default_provider": self.default_provider,
            "default_persona": self.default_persona,
            "providers": [p.public() for p in self.providers.values()],
            "personas": sorted(self.personas),
            "auth_required": bool(self.api_key),
            "allow_custom_endpoint": self.allow_custom_endpoint,
            "custom_endpoint_networks": self.custom_endpoint_networks,
            "cors_origins": self.cors_origins,
            "review_defaults": self.review_defaults,
            "server_github_token_configured": bool(
                os.getenv(self.github_token_env, "")),
        }


def _parse(text: str, path: Path) -> dict[str, Any]:
    """Parse YAML if PyYAML is available, else JSON.

    YAML is preferred because a config file people edit deserves comments;
    JSON works with no extra dependency.
    """
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # noqa: PLC0415 - optional dependency
        except ImportError as exc:  # pragma: no cover - env dependent
            raise ConfigError(
                f"{path.name} is YAML but PyYAML is not installed. Either "
                "'pip install pyyaml' or use a JSON config file."
            ) from exc
        return yaml.safe_load(text) or {}
    return json.loads(text or "{}")


# Kubernetes injects <SERVICE>_PORT=tcp://10.0.0.1:8000 (and friends) into
# every pod, for every Service in the namespace. A Service named review-api
# therefore sets REVIEW_API_PORT to a URL — the very variable this API reads
# as its port — and startup died on int("tcp://..."). A value in that form is
# never one of our settings, so it is treated as unset. The Kubernetes-side
# fix is `enableServiceLinks: false` in the pod spec.
_SERVICE_LINK = re.compile(r"^(tcp|udp|sctp)://", re.IGNORECASE)


def _getenv(name: str) -> str | None:
    """os.getenv, minus Kubernetes service-link values."""
    value = os.getenv(name)
    if value and _SERVICE_LINK.match(value):
        warnings.warn(
            f"ignoring {name}={value!r}: that is a Kubernetes service-link "
            "variable, not a setting (set enableServiceLinks: false in the "
            "pod spec to stop Kubernetes injecting it)", stacklevel=2)
        return None
    return value


def _expand_vars(value: Any, where: str = "config") -> Any:
    """Expand ${VAR} / ${VAR:-fallback} through nested config values.

    A variable with no fallback that is not set is an ERROR rather than an
    empty string: silently producing `base_url: "/v1"` would turn a missing
    environment variable into a confusing failure in the middle of a review,
    and this config's contract is that typos fail at startup.
    """
    if isinstance(value, dict):
        return {k: _expand_vars(v, f"{where}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_vars(v, f"{where}[{i}]") for i, v in enumerate(value)]
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        name, fallback = match.group(1), match.group(2)
        env = _getenv(name)
        if env:
            return env
        if fallback is not None:
            return fallback
        raise ConfigError(
            f"{where} references ${{{name}}} but {name} is not set in the "
            f"environment. Either set it (see .env.example) or give it a "
            f"fallback: ${{{name}:-some-default}}."
        )

    return _VAR_PATTERN.sub(replace, value)


def _coerce_scalars(data: dict[str, Any]) -> dict[str, Any]:
    """Restore declared types that ${VAR} expansion flattened to strings.

    `port: ${REVIEW_API_PORT:-8000}` is a string once expanded, even though
    the plain `port: 8000` it replaces was an int. Coerce back to whatever
    ApiConfig declares so the rest of the program sees consistent types.
    """
    truthy = ("1", "true", "yes", "on")
    for name, spec in ApiConfig.__dataclass_fields__.items():
        value = data.get(name)
        if not isinstance(value, str) or spec.type not in ("int", "bool"):
            continue
        if spec.type == "bool":
            data[name] = value.strip().lower() in truthy
            continue
        try:
            data[name] = int(value.strip())
        except ValueError as exc:
            raise ConfigError(
                f"Configuration key {name!r} must be a whole number, "
                f"got {value!r}."
            ) from exc
    return data


def _resolve_path(value: str, base: Path | None) -> str:
    """Make a relative path absolute against the config file's directory.

    Without this, `output_dir: reports` means a different folder depending on
    the directory you launched from — the classic "where did my report go?"
    on a freshly cloned checkout.
    """
    if not value:
        return value
    path = Path(value).expanduser()
    if path.is_absolute() or base is None:
        return str(path)
    return str((base / path).resolve())


def _env_override(data: dict[str, Any]) -> dict[str, Any]:
    """Apply REVIEW_API_* environment overrides over the file values."""
    mapping = {
        "REVIEW_API_HOST": ("host", str),
        "REVIEW_API_PORT": ("port", int),
        "REVIEW_API_DEBUG": ("debug", lambda v: v not in ("0", "", "false")),
        "REVIEW_API_OUTPUT_DIR": ("output_dir", str),
        "REVIEW_API_DEFAULT_PROVIDER": ("default_provider", str),
        "REVIEW_API_DEFAULT_MODE": ("default_mode", str),
        "REVIEW_API_DEFAULT_PERSONA": ("default_persona", str),
        "REVIEW_API_KEY": ("api_key", str),
    }
    for env_name, (key, caster) in mapping.items():
        raw = _getenv(env_name)
        if raw is not None and raw != "":
            data[key] = caster(raw)
    origins = os.getenv("REVIEW_API_CORS_ORIGINS")
    if origins:
        data["cors_origins"] = [o.strip() for o in origins.split(",") if o.strip()]
    return data


def normalize_endpoint(raw: str) -> str:
    """Turn what a person types into an OpenAI-compatible base URL.

    People paste an address, not a URL. All of these become
    `http://100.83.14.22:1234/v1`:

        100.83.14.22            100.83.14.22:1234
        http://100.83.14.22     http://100.83.14.22:1234/v1

    A full URL that already carries a path is respected as given, so an
    endpoint served under a prefix still works.
    """
    text = (raw or "").strip().rstrip("/")
    if not text:
        raise EndpointError("Endpoint is empty.")
    if "://" not in text:
        text = f"http://{text}"

    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https"):
        raise EndpointError(
            f"Endpoint must use http or https, got {parsed.scheme!r}.")
    if parsed.username or parsed.password:
        # Credentials in a URL end up in logs and error messages.
        raise EndpointError(
            "Do not put credentials in the endpoint URL.")
    if not parsed.hostname:
        raise EndpointError(f"Could not find a host in {raw!r}.")

    netloc = parsed.hostname
    if ":" in netloc:                     # bare IPv6 needs brackets back
        netloc = f"[{netloc}]"
    port = parsed.port
    if port is None and parsed.scheme == "http":
        port = _LMSTUDIO_DEFAULT_PORT     # what LM Studio serves on
    if port is not None:
        netloc = f"{netloc}:{port}"

    path = parsed.path or ""
    if not path or path == "/":
        path = "/v1"                      # OpenAI-compatible convention
    return f"{parsed.scheme}://{netloc}{path}"


def check_endpoint_allowed(base_url: str,
                           networks: Sequence[str] | None = None) -> str:
    """Confirm a caller-supplied endpoint points inside an allowed network.

    Without this the API would POST repository source code to any address a
    request names — an exfiltration channel and an SSRF pivot, made worse by
    the API being unauthenticated and CORS-open by default. Restricting to
    private and Tailscale ranges costs nothing here, because reaching a cloud
    model is what the configured cloud PROVIDERS are for.

    Returns the host that was checked. Note the honest limit: the name is
    resolved here and again by the HTTP client, so a hostile DNS server could
    answer differently each time. Prefer literal IPs for anything sensitive.
    """
    allowed = [ip_network(n) for n in (networks or DEFAULT_ENDPOINT_NETWORKS)]
    host = urlparse(base_url).hostname or ""

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EndpointError(
            f"Cannot resolve {host!r}. Check the address, and that you are "
            f"connected to the same network (for Tailscale: `tailscale status`)."
        ) from exc

    resolved = {info[4][0] for info in infos}
    for address in resolved:
        ip = ip_address(address.split("%")[0])       # strip zone id
        if not any(ip in net for net in allowed):
            raise EndpointError(
                f"{host} resolves to {ip}, which is outside the networks this "
                f"server may be pointed at ({', '.join(str(n) for n in allowed)}). "
                "A custom endpoint is meant for a model on your own or your "
                "team's private network — use a configured cloud provider to "
                "reach a hosted model."
            )
    return host


def load_dotenv(path: str | Path | None = None) -> Path | None:
    """Populate os.environ from a .env file, without adding a dependency.

    Docker Compose reads .env by itself; a plain `python -m review_api.app`
    does not, and teammates edit exactly one file to configure their machine.
    Called from main() ONLY — importing this package into another process
    must never silently absorb somebody's local secrets file, and tests must
    not depend on whether one exists.

    A real environment variable always wins over the file, so
    `GOOGLE_API_KEY=... python -m review_api.app` still overrides it.
    """
    candidates = [Path(path)] if path else [
        Path(__file__).resolve().parents[2] / ".env",   # repository root
        Path.cwd() / ".env",
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.removeprefix("export ").partition("=")
            key, value = key.strip(), value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key and value and key not in os.environ:
                os.environ[key] = value
        return candidate
    return None


def find_config_path(explicit: str | None = None) -> Path | None:
    """Locate the config file: explicit arg, env var, then conventions."""
    for candidate in (explicit, os.getenv("REVIEW_API_CONFIG")):
        if candidate:
            path = Path(candidate)
            if not path.is_file():
                raise ConfigError(f"Config file not found: {path}")
            return path
    for name in _CANDIDATES:
        path = Path(name)
        if path.is_file():
            return path
    return None


def load_config(path: str | None = None) -> ApiConfig:
    """Build the effective configuration (file + environment overrides).

    Running with no config file at all is supported: the defaults describe a
    local LM Studio, so the API works out of the box for the demo.
    """
    found = find_config_path(path)
    data: dict[str, Any] = {}
    if found is not None:
        data = _parse(found.read_text(encoding="utf-8"), found)
        if not isinstance(data, dict):
            raise ConfigError(f"{found} must contain a mapping at the top level.")
        data = _expand_vars(data, found.name)

    raw_providers = data.pop("providers", None) or {}
    raw_personas = data.pop("personas", None) or {}
    data = _coerce_scalars(_env_override(data))

    # Relative paths belong to the config file, not to the shell's cwd.
    base_dir = found.parent.resolve() if found is not None else None
    if data.get("output_dir"):
        data["output_dir"] = _resolve_path(str(data["output_dir"]), base_dir)

    providers: dict[str, Provider] = {}
    for name, spec in raw_providers.items():
        if not isinstance(spec, dict):
            raise ConfigError(f"Provider {name!r} must be a mapping.")
        if not spec.get("base_url"):
            raise ConfigError(f"Provider {name!r} is missing 'base_url'.")
        providers[name] = Provider(name=name, **spec)

    if not providers:
        # Zero-config fallback: the local LM Studio this project already uses.
        providers["lmstudio"] = Provider(
            name="lmstudio",
            base_url=os.getenv("LMSTUDIO_BASE_URL",
                               "http://localhost:1234/v1"),
            api_key_default=os.getenv("LMSTUDIO_API_KEY", "lm-studio"),
            location="on_prem",
            description="Local LM Studio (default when no config file exists)",
        )

    # Keys this API used to accept. They are dropped with a warning instead
    # of failing startup: every teammate copied api.example.yaml into their
    # own api.yaml, and an upgrade should not break a file they never asked
    # to change.
    for retired, why in _RETIRED_KEYS.items():
        if retired in data:
            data.pop(retired)
            warnings.warn(f"config key {retired!r} is no longer used: {why}",
                          stacklevel=2)

    known = {f for f in ApiConfig.__dataclass_fields__}  # noqa: PLC0208
    unknown = set(data) - known
    if unknown:
        raise ConfigError(
            f"Unknown configuration key(s): {', '.join(sorted(unknown))}")

    cfg = ApiConfig(**data)
    cfg.providers = providers
    cfg.personas = dict(raw_personas)
    cfg.config_path = str(found) if found else "(defaults, no config file)"
    if not cfg.default_provider:
        cfg.default_provider = next(iter(providers))
    # Validate the wiring now, so a typo fails at startup, not mid-review.
    cfg.provider(cfg.default_provider)
    if not cfg.api_key:
        cfg.api_key = os.getenv("REVIEW_API_KEY", "")
    return cfg
