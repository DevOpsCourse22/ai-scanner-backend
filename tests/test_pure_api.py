"""The review API is an API and nothing else.

The test console used to be served from here at `/`. It is a separate
service now (frontend/, image review-console), so these tests pin the
backend's side of that split: no HTML, no static files, and probe endpoints
a kubelet can call without credentials.
"""

import warnings

import pytest

from review_api.config import ApiConfig, load_config

flask = pytest.importorskip("flask")


def _app(tmp_path, **overrides):
    from review_api.app import create_app

    cfg = ApiConfig(output_dir=str(tmp_path), **overrides)
    app = create_app(cfg=cfg)
    app.config.update(TESTING=True)
    return app


# ---------------- no UI surface ----------------

def test_root_is_a_json_descriptor_not_a_page(tmp_path):
    r = _app(tmp_path).test_client().get("/")
    assert r.status_code == 200
    assert r.mimetype == "application/json"
    body = r.get_json()
    assert body["service"] == "review-api"
    assert body["kind"] == "api"
    assert "review-console" in body["note"]       # says where the UI went


def test_the_descriptor_reveals_no_configuration(tmp_path):
    """Unauthenticated, so it must not name providers, paths or settings."""
    body = _app(tmp_path).test_client().get("/").get_data(as_text=True)
    for leak in ("lmstudio", "localhost:1234", str(tmp_path), "output_dir",
                 "api_key", "providers"):
        assert leak not in body


def test_no_static_route_is_registered(tmp_path):
    """Flask registers /static by default. A pure API must not."""
    app = _app(tmp_path)
    assert app.static_folder is None
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert "static" not in endpoints


@pytest.mark.parametrize("path", ["/index.html", "/static/index.html",
                                  "/favicon.ico", "/console.json"])
def test_nothing_that_looks_like_a_ui_asset_is_served(tmp_path, path):
    assert _app(tmp_path).test_client().get(path).status_code == 404


def test_no_route_ever_answers_with_html(tmp_path):
    """Walk every GET route that takes no parameters: none returns a page."""
    app = _app(tmp_path)
    client = app.test_client()
    for rule in app.url_map.iter_rules():
        if "GET" not in rule.methods or rule.arguments:
            continue
        r = client.get(rule.rule)
        assert r.mimetype != "text/html", f"{rule.rule} returned HTML"


def test_the_backend_package_ships_no_console(tmp_path):
    """A leftover index.html inside the package would be found and served by
    anything that went looking — the old resolver did exactly that."""
    from pathlib import Path

    import review_api
    package = Path(review_api.__file__).parent
    assert not list(package.rglob("*.html"))
    assert not hasattr(ApiConfig(), "resolve_frontend_dir")


# ---------------- probes ----------------

def test_healthz_and_readyz_answer_without_the_api_key(tmp_path):
    """A kubelet sends no X-API-Key. A liveness probe answered with 401
    restarts a healthy pod forever — and the old compose healthcheck, which
    used /api/v1/health, would have gone unhealthy the moment a key was set."""
    client = _app(tmp_path, api_key="s3cret").test_client()
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    # ...while the API itself stays locked.
    assert client.get("/api/v1/health").status_code == 401
    assert client.get("/api/v1/reports").status_code == 401


def test_healthz_checks_nothing_external(tmp_path, monkeypatch):
    """An LLM outage must not make Kubernetes restart a healthy API."""
    from code_review_mcp import llm

    def boom(*a, **k):
        raise AssertionError("liveness must not touch the model")

    monkeypatch.setattr(llm, "make_client", boom)
    r = _app(tmp_path).test_client().get("/healthz")
    assert r.status_code == 200 and r.get_json() == {"status": "ok"}


def test_readyz_fails_when_reports_cannot_be_written(tmp_path, monkeypatch):
    from review_api import app as app_module

    client = _app(tmp_path).test_client()
    monkeypatch.setattr(app_module.os, "access", lambda path, mode: False)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert "not writable" in r.get_json()["reason"]


# ---------------- config ----------------

def test_an_old_config_with_frontend_dir_still_loads(tmp_path):
    """Every teammate copied api.example.yaml into their own api.yaml. An
    upgrade must not turn a key they never touched into a startup error."""
    (tmp_path / "api.yaml").write_text(
        "frontend_dir: ../../frontend\n"
        "providers:\n  p:\n    base_url: http://x/v1\n", encoding="utf-8")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = load_config(str(tmp_path / "api.yaml"))
    assert set(cfg.providers) == {"p"}
    assert any("frontend_dir" in str(w.message) for w in caught)


def test_effective_config_no_longer_mentions_a_frontend(tmp_path):
    body = _app(tmp_path).test_client().get("/api/v1/config").get_json()
    assert "frontend_dir" not in body


def test_other_unknown_keys_are_still_rejected(tmp_path):
    """Tolerating one retired key must not make the config lax in general."""
    from review_api.config import ConfigError

    (tmp_path / "api.yaml").write_text("fronted_dir: typo\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="fronted_dir"):
        load_config(str(tmp_path / "api.yaml"))


# ---------------- Kubernetes service-link variables ----------------

def test_a_service_named_review_api_cannot_crash_startup(tmp_path, monkeypatch):
    """Found by deploying to minikube: Kubernetes injects
    REVIEW_API_PORT=tcp://<cluster-ip>:8000 for a Service named review-api,
    and this API reads REVIEW_API_PORT as its port. The pod crash-looped on
    int('tcp://10.103.82.121:8000')."""
    monkeypatch.setenv("REVIEW_API_PORT", "tcp://10.103.82.121:8000")
    (tmp_path / "api.yaml").write_text(
        "port: ${REVIEW_API_PORT:-8000}\n"
        "providers:\n  p:\n    base_url: http://x/v1\n", encoding="utf-8")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = load_config(str(tmp_path / "api.yaml"))
    assert cfg.port == 8000
    assert any("service-link" in str(w.message) for w in caught)


def test_service_links_cannot_corrupt_an_interpolated_url(tmp_path, monkeypatch):
    """The same injection reaches ${VAR} expansion: a Service named
    tailscale-lmstudio would have turned the provider URL into
    http://host:tcp://10.1.2.3:1234/v1."""
    monkeypatch.setenv("TAILSCALE_LMSTUDIO_PORT", "tcp://10.1.2.3:1234")
    (tmp_path / "api.yaml").write_text(
        "providers:\n  t:\n"
        "    base_url: http://gpu:${TAILSCALE_LMSTUDIO_PORT:-1234}/v1\n",
        encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cfg = load_config(str(tmp_path / "api.yaml"))
    assert cfg.providers["t"].base_url == "http://gpu:1234/v1"


def test_a_real_port_setting_still_wins(tmp_path, monkeypatch):
    """Only the tcp:// form is ignored; an actual override still applies."""
    monkeypatch.setenv("REVIEW_API_PORT", "9123")
    (tmp_path / "api.yaml").write_text(
        "providers:\n  p:\n    base_url: http://x/v1\n", encoding="utf-8")
    assert load_config(str(tmp_path / "api.yaml")).port == 9123


def test_readyz_fails_when_there_is_nowhere_to_clone(tmp_path, monkeypatch):
    """Found under a read-only root filesystem with no volume on /tmp: every
    review failed with 'No usable temporary directory found' while /readyz
    still said ready, so the pod took traffic it could not serve."""
    from review_api import app as app_module

    client = _app(tmp_path).test_client()

    def nowhere():
        raise FileNotFoundError("No usable temporary directory found")

    monkeypatch.setattr(app_module.tempfile, "gettempdir", nowhere)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert "/tmp" in r.get_json()["reason"]
    # ...and liveness is unaffected: the process itself is fine.
    assert client.get("/healthz").status_code == 200
