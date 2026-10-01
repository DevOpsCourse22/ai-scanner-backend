"""Reasoning models that stream their thinking in a separate delta field.

Observed against LM Studio on 2026-09-21 with `google/gemma-4-12b-qat`:
every token arrived as `delta.reasoning_content` and `delta.content` stayed
empty until the model had finished thinking. Both count against max_tokens,
so a budget exhausted mid-reasoning produced an empty response — which the
code then reported as "no JSON object found: line 1 column 1 (char 0)", a
message that reads like a prompt or parsing bug rather than a model that
never got as far as answering.

A 6-line test file needed 893 tokens (641 of them reasoning) and still hit
`finish_reason="length"`, so this is the normal case for such a model, not
an edge case.
"""

from types import SimpleNamespace

import pytest

from code_review_mcp import llm
from code_review_mcp.llm import LLMError


def _delta(*, content=None, reasoning=None, finish=None):
    """One streamed chunk, shaped like the OpenAI SDK's objects.

    `reasoning_content` is not part of the OpenAI schema — the SDK surfaces
    it as an extra attribute — so it is set as a plain attribute here, and
    left off entirely when a chunk has none.
    """
    delta = SimpleNamespace(content=content)
    if reasoning is not None:
        delta.reasoning_content = reasoning
    choice = SimpleNamespace(delta=delta, finish_reason=finish)
    return SimpleNamespace(model="test-model", choices=[choice])


def _client(chunks):
    """A stand-in OpenAI client that replays a fixed list of chunks."""
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return iter(chunks(len(calls) - 1))

    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
        calls=calls,
    )
    return client


@pytest.fixture(autouse=True)
def _no_model_lookup(monkeypatch):
    monkeypatch.setattr(llm, "resolve_model", lambda client: "test-model")


def test_reasoning_only_response_is_reported_as_never_answered(monkeypatch):
    """The failure a user actually sees must name the cause. "No JSON
    object found" sends them hunting for a prompt bug; the model simply
    never started writing."""
    monkeypatch.setattr(llm.settings, "json_retries", 2)

    def chunks(_attempt):
        return [_delta(reasoning="thinking " * 10) for _ in range(5)] + [
            _delta(finish="length")
        ]

    with pytest.raises(LLMError) as err:
        llm._json_completion(_client(chunks), [{"role": "user", "content": "x"}],
                             None, 4096, "demo.py")

    message = str(err.value)
    assert "never answered" in message
    assert "reasoning" in message
    assert "no JSON object found" not in message


def test_budget_is_raised_once_then_capped_instead_of_retried_forever(
        monkeypatch):
    """Doubling the budget is the right first move - the answer cannot
    start until the thinking stops. Doing it indefinitely is not: each
    attempt pays the full generation time again before failing, which on a
    slow endpoint is minutes per file across a whole repository."""
    monkeypatch.setattr(llm.settings, "json_retries", 5)

    def chunks(_attempt):
        return [_delta(reasoning="thinking"), _delta(finish="length")]

    client = _client(chunks)
    with pytest.raises(LLMError):
        llm._json_completion(client, [{"role": "user", "content": "x"}],
                             None, 4096, "demo.py")

    budgets = [call["max_tokens"] for call in client.calls]
    assert budgets == [4096, 8192, 16000]  # doubled, then stopped at the cap
    assert budgets[-1] == llm.REASONING_TOKEN_CEILING


def test_content_is_still_read_when_the_model_finishes_thinking():
    """The same model answers normally once its reasoning fits in the
    budget - reasoning must not be mistaken for the answer, nor block it."""
    def chunks(_attempt):
        return [
            _delta(reasoning="let me look at this file"),
            _delta(content='{"file": "demo.py", '),
            _delta(content='"summary": "fine", "issues": [], '),
            _delta(content='"positives": [], "score": 8}', finish="stop"),
        ]

    result = llm._json_completion(_client(chunks),
                                  [{"role": "user", "content": "x"}],
                                  None, 4096, "demo.py")

    assert result["file"] == "demo.py"
    assert result["score"] == 8


def test_reasoning_text_is_never_used_as_the_answer():
    """Reasoning is the model arguing with itself. A JSON object inside it
    may be one it went on to reject, so it must not be parsed as a review
    just because it happens to be well-formed."""
    rejected = '{"file": "demo.py", "summary": "WRONG", "issues": [], ' \
               '"positives": [], "score": 1}'

    def chunks(_attempt):
        return [_delta(reasoning=f"maybe {rejected} ... no, that is wrong"),
                _delta(finish="length")]

    with pytest.raises(LLMError) as err:
        llm._json_completion(_client(chunks), [{"role": "user", "content": "x"}],
                             None, 16000, "demo.py")

    assert "WRONG" not in str(err.value)


def test_a_model_without_reasoning_fields_is_unaffected():
    """Plain models send no `reasoning_content` at all; reading it must be
    optional, not assumed."""
    def chunks(_attempt):
        return [_delta(content='{"file": "d.py", "summary": "ok", '),
                _delta(content='"issues": [], "positives": [], "score": 9}',
                       finish="stop")]

    result = llm._json_completion(_client(chunks),
                                  [{"role": "user", "content": "x"}],
                                  None, 4096, "d.py")
    assert result["score"] == 9


# ---------------- which model actually answered ----------------
#
# LM Studio can be configured with a default model that serves every
# request regardless of the model the request names (Elad enabled this on
# 2026-09-21, after two models loaded at once exhausted the GPU). From
# then on "what we asked for" and "what answered" can differ, and only one
# of them belongs in a report.

def _report(monkeypatch, *, requested, served):
    from code_review_mcp import llm as llm_mod, review as review_mod

    monkeypatch.setattr(review_mod.settings, "lm_model", requested)
    monkeypatch.setattr(llm_mod, "last_model_used", served)
    return review_mod._build_report(
        {"repo_url": "https://github.com/o/r", "commit": "abc", "files": []},
        [], [])


def test_report_names_the_model_that_answered_not_the_one_requested(
        monkeypatch):
    """In a security report, which model produced a finding is part of the
    finding. Attributing it to a model that never saw the code is wrong
    even when the review itself is good."""
    report = _report(monkeypatch, requested="gemma-4-12b", served="gemma-4-26b")
    assert report["model"] == "gemma-4-26b"


def test_a_mismatch_is_recorded_rather_than_quietly_resolved(monkeypatch):
    """The endpoint is not serving what this deployment thinks it asked
    for. Silently using the right name would hide that."""
    report = _report(monkeypatch, requested="gemma-4-12b", served="gemma-4-26b")
    assert report["model_requested"] == "gemma-4-12b"


def test_no_mismatch_field_when_they_agree(monkeypatch):
    report = _report(monkeypatch, requested="gemma-4-26b", served="gemma-4-26b")
    assert "model_requested" not in report


def test_requested_name_is_used_when_the_endpoint_names_nothing(monkeypatch):
    """Not every endpoint reports a model on its responses; the configured
    name is still better than nothing."""
    report = _report(monkeypatch, requested="gemma-4-26b", served=None)
    assert report["model"] == "gemma-4-26b"
    assert "model_requested" not in report
