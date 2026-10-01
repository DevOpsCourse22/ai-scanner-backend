"""Flask HTTP control plane for AI code reviews.

Wraps the verified review pipeline (`code_review_mcp`) in a REST API so any
client — the bundled demo UI, a CI job, or another service — can request
reviews against either an on-prem or a cloud LLM.
"""

from .config import ApiConfig, ConfigError, Provider, load_config

__all__ = ["ApiConfig", "ConfigError", "Provider", "load_config", "create_app"]

__version__ = "0.1.0"


def create_app(*args, **kwargs):
    """Lazy re-export so `import review_api` does not require Flask."""
    from .app import create_app as _create_app

    return _create_app(*args, **kwargs)
