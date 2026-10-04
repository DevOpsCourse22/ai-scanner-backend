"""AI services a site admin can pick in Settings, and how to reach each.

The gateway stores ONE choice for the whole site (preset, model, API key)
and sends it with every review it starts or resumes. This module turns that
choice into an endpoint review-api will actually call, and it is the reason
the choice is a preset NAME rather than an address:

* A cloud preset's address is fixed here, in code. Nobody can make
  review-api POST repository source code to an address of their choosing
  by editing a setting (the exfiltration / SSRF concern spelled out in
  config.check_endpoint_allowed).
* The one preset that takes an address, "local", goes through the same
  private-network check as every other caller-supplied endpoint.

Every cloud preset is reached through its OpenAI-compatible endpoint, which
is what the engine's one client speaks; no provider-specific SDK is needed.
The API key is never stored by review-api: it lives in memory for the run
(local mode) or in the per-attempt Kubernetes Secret (cluster mode).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Preset:
    name: str
    label: str
    # Empty for "local": the address comes from the setting, or from the
    # server's configured default provider when the setting leaves it out.
    base_url: str
    location: str              # "on_prem" | "cloud"
    needs_key: bool
    example_model: str
    key_hint: str = ""


PRESETS: dict[str, Preset] = {p.name: p for p in (
    Preset("local", "LM Studio, Ollama or vLLM on your network", "",
           "on_prem", False, "google/gemma-4-26b-a4b-qat",
           "Usually none. Only if your server was set up to require one."),
    Preset("openai", "OpenAI", "https://api.openai.com/v1",
           "cloud", True, "gpt-4.1-mini",
           "platform.openai.com, API keys"),
    Preset("anthropic", "Anthropic", "https://api.anthropic.com/v1/",
           "cloud", True, "claude-sonnet-5-5",
           "console.anthropic.com, API keys"),
    Preset("google", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai/",
           "cloud", True, "gemini-2.5-flash",
           "aistudio.google.com, Get API key"),
    Preset("groq", "Groq", "https://api.groq.com/openai/v1",
           "cloud", True, "llama-3.3-70b-versatile",
           "console.groq.com, API keys"),
    Preset("openrouter", "OpenRouter", "https://openrouter.ai/api/v1",
           "cloud", True, "qwen/qwen-2.5-coder-32b-instruct",
           "openrouter.ai, Keys"),
    Preset("mistral", "Mistral", "https://api.mistral.ai/v1",
           "cloud", True, "codestral-latest",
           "console.mistral.ai, API keys"),
)}


# Anthropic's OpenAI-compatible layer covers chat completions, but GET
# /v1/models is its native endpoint: it refuses a request without an
# anthropic-version header ("anthropic-version: header is required") and
# reads the key from x-api-key, not the Bearer header the OpenAI client
# sends. Only the model list (Test connection in Settings) needs these.
ANTHROPIC_VERSION = "2023-06-01"


def models_headers(base_url: str, api_key: str) -> dict[str, str]:
    """Extra headers listing a service's models needs, by its address."""
    if base_url.startswith(PRESETS["anthropic"].base_url.rstrip("/")):
        return {"anthropic-version": ANTHROPIC_VERSION, "x-api-key": api_key}
    return {}


class PresetError(ValueError):
    """The AI service choice cannot be used as given."""


def public_presets() -> list[dict[str, Any]]:
    """What Settings shows. Addresses included: they are public facts."""
    return [{"name": p.name, "label": p.label, "location": p.location,
             "base_url": p.base_url or None, "needs_key": p.needs_key,
             "example_model": p.example_model, "key_hint": p.key_hint}
            for p in PRESETS.values()]


def parse_llm(raw: Any) -> dict[str, str] | None:
    """Validate the `llm` object of a request body; None when absent.

    Returns {"preset", "endpoint", "model", "api_key"} with every value a
    stripped string. The endpoint is checked by the caller (it needs the
    server's network allowlist), the rest here.
    """
    if raw in (None, {}, ""):
        return None
    if not isinstance(raw, dict):
        raise PresetError("llm must be an object.")
    name = str(raw.get("preset") or "").strip().lower()
    preset = PRESETS.get(name)
    if preset is None:
        raise PresetError(f"Unknown AI service {name!r}. Choose one of: "
                          + ", ".join(PRESETS) + ".")
    out = {key: str(raw.get(key) or "").strip()
           for key in ("endpoint", "model", "api_key")}
    out["preset"] = name
    if out["endpoint"] and preset.base_url:
        raise PresetError(f"{preset.label} has a fixed address; only the "
                          "'local' service takes one.")
    if preset.needs_key and not out["api_key"]:
        raise PresetError(f"{preset.label} needs an API key. Add it in "
                          "Settings, AI model.")
    if len(out["api_key"]) > 4096 or any(c in out["api_key"] for c in "\r\n"):
        raise PresetError("That API key is not valid.")
    if len(out["model"]) > 255:
        raise PresetError("The model name is too long.")
    return out
