"""Models that refuse a sampling temperature.

Observed against Anthropic's OpenAI-compatible endpoint on 2026-10-09 with
`claude-haiku-5-5`: every request carrying `temperature` was answered with
400 "`temperature` is deprecated for this model.", whatever the value. The
engine sent REVIEW_TEMPERATURE on every call, so a deep review failed 165 of
its 167 files with that one error and reported nothing.
"""

from types import SimpleNamespace

import httpx
import pytest
from openai import BadRequestError

from code_review_mcp import llm
from code_review_mcp.config import _optional_float


def _bad_request(message):
    request = httpx.Request("POST", "https://api.example.test/v1/chat/completions")
    response = httpx.Response(400, request=request)
    body = {"error": {"code": "invalid_request_error", "message": message}}
    return BadRequestError(f"Error code: 400 - {body}", response=response, body=body)


def _answer():
    delta = SimpleNamespace(content='{"issues": []}')
    choice = SimpleNamespace(delta=delta, finish_reason="stop")
    return [SimpleNamespace(model="test-model", choices=[choice])]


def _client(refuse):
    """A stand-in client that answers 400 when `refuse(kwargs)` says so."""
    calls = []

    def create(**kwargs):
        calls.append(dict(kwargs))
        error = refuse(kwargs)
        if error:
            raise _bad_request(error)
        return iter(_answer())

    return SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
        calls=calls,
    )


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.setattr(llm, "resolve_model", lambda client: "test-model")
    monkeypatch.setattr(llm, "_no_temperature", set())
    monkeypatch.setattr(llm.settings, "temperature", 0.2)


def _refuses_temperature(kwargs):
    if "temperature" in kwargs:
        return "`temperature` is deprecated for this model."
    return None


def test_a_refused_temperature_is_dropped_and_the_request_retried():
    client = _client(_refuses_temperature)

    content, _, _ = llm._stream_completion(
        client, [{"role": "user", "content": "x"}], None, 1024)

    assert content == '{"issues": []}'
    assert "temperature" in client.calls[0]
    assert "temperature" not in client.calls[1]


def test_later_requests_to_that_model_leave_temperature_out():
    """One failed round trip per review, not one per file."""
    client = _client(_refuses_temperature)
    for _ in range(3):
        llm._stream_completion(client, [{"role": "user", "content": "x"}],
                               None, 1024)

    assert len(client.calls) == 4
    assert all("temperature" not in call for call in client.calls[1:])


def test_a_model_that_takes_temperature_still_gets_it():
    client = _client(lambda kwargs: None)

    llm._stream_completion(client, [{"role": "user", "content": "x"}],
                           None, 1024)

    assert len(client.calls) == 1
    assert client.calls[0]["temperature"] == 0.2


def test_other_bad_requests_are_not_swallowed():
    client = _client(lambda kwargs: "max_tokens is too large")

    with pytest.raises(BadRequestError):
        llm._stream_completion(client, [{"role": "user", "content": "x"}],
                               None, 1024)
    assert len(client.calls) == 1


def test_temperature_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(llm.settings, "temperature", None)
    client = _client(_refuses_temperature)

    llm._stream_completion(client, [{"role": "user", "content": "x"}],
                           None, 1024)

    assert len(client.calls) == 1
    assert "temperature" not in client.calls[0]


@pytest.mark.parametrize("raw, expected", [
    ("0.2", 0.2), ("0", 0.0), ("", None), ("none", None), (" None ", None),
])
def test_review_temperature_env_values(raw, expected):
    assert _optional_float(raw) == expected
