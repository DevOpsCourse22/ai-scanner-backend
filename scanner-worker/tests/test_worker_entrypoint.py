"""entrypoint.py: env in, run_review() call, exit code + termination log out.

Most tests replace run_review with a fake, because what is under test is the
wrapper: which inputs it accepts, what it hands the engine, which exit code
each failure becomes, and that the token never reaches a log line. The last
test runs the REAL pipeline (only the clone and the LLM are faked) through
a crash and a retry, which is the contract's whole reason for REVIEW_ID.
"""

from __future__ import annotations

import json
import logging
import os

import pytest

import entrypoint
from code_review_mcp import pipeline
from code_review_mcp.llm import LLMUnavailableError
from code_review_mcp.repo_ingest import IngestError

TOKEN = "ghp_TESTTOKENtesttoken0123456789abcdefXY"


@pytest.fixture
def job_env(monkeypatch, tmp_path):
    """The environment a Job would get, pointed at temp directories."""
    ws = tmp_path / "workspace"
    values = {
        "REPO_URL": "https://github.com/owner/repo",
        "REVIEW_ID": "rev-001",
        "MODE": "brief",
        "LMSTUDIO_BASE_URL": "http://llm.invalid:1234/v1",
        "SYSTEM_PROMPT": "Strict security reviewer",
        "GITHUB_TOKEN": TOKEN,
        "REVIEW_OUTPUT_DIR": str(tmp_path / "reports"),
        "TMPDIR": str(ws),
        "HOME": str(ws / "home"),
        "TRIVY_CACHE_DIR": str(ws / ".cache" / "trivy"),
        "TERMINATION_LOG": str(tmp_path / "termination-log"),
    }
    for name in ("BRANCH", "GH_TOKEN", "GITHUB_TOKEN_FILE", "COMMIT",
                 "LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    # Keep main()'s SIGTERM handler from outliving the test.
    import signal
    monkeypatch.setattr(signal, "signal", lambda *a, **k: None)
    return tmp_path


def termination(tmp_path) -> str:
    path = tmp_path / "termination-log"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def fake_run_review(calls, *, report=None, raises=None, write=True):
    def run(repo_url, system_prompt, output_path, **kwargs):
        calls.append({"repo_url": repo_url, "system_prompt": system_prompt,
                      "output_path": output_path,
                      "env_token": os.environ.get("GITHUB_TOKEN"),
                      **kwargs})
        if raises:
            raise raises
        out = pipeline._resolve_output(output_path)
        if write:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("{}", encoding="utf-8")
        return {**(report or {}), "_output_path": str(out)}
    return run


@pytest.fixture
def output_dir(monkeypatch, job_env):
    from code_review_mcp.config import settings
    monkeypatch.setattr(settings, "output_dir", str(job_env / "reports"))
    return job_env / "reports"


# ---------------- the happy path ----------------

def test_success_exits_0_and_hands_the_engine_the_contract_inputs(
        monkeypatch, job_env, output_dir):
    calls = []
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(calls))
    monkeypatch.setenv("BRANCH", "develop")

    assert entrypoint.main() == entrypoint.EXIT_OK
    (call,) = calls
    assert call["repo_url"] == "https://github.com/owner/repo"
    assert call["system_prompt"] == "Strict security reviewer"
    # <REVIEW_ID>.json => .md/.partial.json/.findings.json share the stem.
    assert call["output_path"] == "rev-001.json"
    assert call["mode"] == "brief" and call["branch"] == "develop"
    assert call["github_token"] == TOKEN
    assert (output_dir / "rev-001.json").is_file()
    assert termination(job_env) == ""


def test_workspace_dirs_are_created_because_an_emptydir_starts_empty(
        monkeypatch, job_env, output_dir):
    monkeypatch.setattr(pipeline, "run_review", fake_run_review([]))
    assert entrypoint.main() == 0
    ws = job_env / "workspace"
    assert (ws / "home").is_dir() and (ws / ".cache" / "trivy").is_dir()


def test_no_branch_means_the_default_branch(monkeypatch, job_env, output_dir):
    calls = []
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(calls))
    assert entrypoint.main() == 0
    assert calls[0]["branch"] is None
    assert calls[0]["commit"] is None       # no COMMIT: the branch tip


def test_commit_pins_the_review(monkeypatch, job_env, output_dir):
    """v3: a resumed review is pinned to its checkpoint's commit."""
    calls = []
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(calls))
    monkeypatch.setenv("COMMIT", "AB" * 20)
    assert entrypoint.main() == 0
    assert calls[0]["commit"] == "ab" * 20


def test_findings_in_the_code_are_still_a_success(monkeypatch, job_env,
                                                  output_dir):
    report = {"failures": [{"file": "a.py", "error": "bad json"}],
              "stats": {"issues": 40}}
    monkeypatch.setattr(pipeline, "run_review",
                        fake_run_review([], report=report))
    assert entrypoint.main() == 0


# ---------------- the token ----------------

def test_token_leaves_the_environment_before_the_engine_runs(
        monkeypatch, job_env, output_dir):
    """Scanners are child processes: whatever is in os.environ, they get."""
    calls = []
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(calls))
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    assert entrypoint.main() == 0
    assert calls[0]["env_token"] is None
    assert "GITHUB_TOKEN" not in os.environ and "GH_TOKEN" not in os.environ


def test_token_can_come_from_a_mounted_secret_file(monkeypatch, job_env,
                                                   output_dir):
    secret = job_env / "token"
    secret.write_text(TOKEN + "\n", encoding="utf-8")
    monkeypatch.delenv("GITHUB_TOKEN")
    monkeypatch.setenv("GITHUB_TOKEN_FILE", str(secret))
    calls = []
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(calls))
    assert entrypoint.main() == 0
    assert calls[0]["github_token"] == TOKEN


def test_no_token_is_a_public_clone(monkeypatch, job_env, output_dir):
    monkeypatch.delenv("GITHUB_TOKEN")
    calls = []
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(calls))
    assert entrypoint.main() == 0
    assert calls[0]["github_token"] is None


def test_the_token_never_reaches_a_log_line_or_the_pod_status(
        monkeypatch, job_env, output_dir, caplog):
    def leaky(*args, **kwargs):
        logging.getLogger("code_review_mcp.repo_ingest").info(
            "cloning with %s", TOKEN)
        raise RuntimeError(f"something echoed the token: {TOKEN}")

    monkeypatch.setattr(pipeline, "run_review", leaky)
    with caplog.at_level(logging.INFO):
        assert entrypoint.main() == entrypoint.EXIT_RETRYABLE
    assert TOKEN not in caplog.text
    assert "***" in caplog.text
    assert TOKEN not in termination(job_env)
    assert "supplied" in caplog.text          # presence is logged, not value


LLM_KEY = "sk-live-TESTKEYtestkey0123456789"


def test_the_llm_key_reaches_the_engine_and_leaves_the_environment(
        monkeypatch, job_env, output_dir):
    from code_review_mcp.config import settings as engine_settings
    monkeypatch.setenv("LLM_API_KEY", LLM_KEY)
    monkeypatch.setattr(engine_settings, "lm_api_key", "lm-studio")
    seen = {}

    def run(*args, **kwargs):
        seen["key"] = engine_settings.lm_api_key
        seen["env"] = os.environ.get("LLM_API_KEY")
        return fake_run_review([])(*args, **kwargs)

    monkeypatch.setattr(pipeline, "run_review", run)
    assert entrypoint.main() == 0
    assert seen == {"key": LLM_KEY, "env": None}   # scanners can't inherit it


def test_without_an_llm_key_the_server_default_stays(monkeypatch, job_env,
                                                     output_dir):
    from code_review_mcp.config import settings as engine_settings
    monkeypatch.setattr(engine_settings, "lm_api_key", "lm-studio")
    monkeypatch.setattr(pipeline, "run_review", fake_run_review([]))
    assert entrypoint.main() == 0
    assert engine_settings.lm_api_key == "lm-studio"


def test_the_llm_key_never_reaches_a_log_line_or_the_pod_status(
        monkeypatch, job_env, output_dir, caplog):
    monkeypatch.setenv("LLM_API_KEY", LLM_KEY)

    def leaky(*args, **kwargs):
        logging.getLogger("code_review_mcp.llm").info("calling with %s", LLM_KEY)
        raise RuntimeError(f"401 for key {LLM_KEY}")

    monkeypatch.setattr(pipeline, "run_review", leaky)
    with caplog.at_level(logging.INFO):
        assert entrypoint.main() == entrypoint.EXIT_RETRYABLE
    assert LLM_KEY not in caplog.text
    assert LLM_KEY not in termination(job_env)


# ---------------- permanent failures: exit 2 ----------------

def test_missing_inputs_are_all_reported_at_once(monkeypatch, job_env):
    for name in ("REPO_URL", "MODE", "SYSTEM_PROMPT"):
        monkeypatch.delenv(name)
    called = []
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(called))
    assert entrypoint.main() == entrypoint.EXIT_PERMANENT
    message = termination(job_env)
    assert message.startswith("permanent:")
    for name in ("REPO_URL", "MODE", "SYSTEM_PROMPT"):
        assert name in message
    assert not called
    assert message.count("\n") == 1           # one line for the Pod status


@pytest.mark.parametrize("name,value", [
    ("MODE", "thorough"),
    ("REVIEW_ID", "../../etc/passwd"),
    ("REVIEW_ID", ".hidden"),
    ("REVIEW_ID", "a/b"),
    ("COMMIT", "abc123"),
    ("COMMIT", "--upload-pack=x"),
])
def test_bad_inputs_are_permanent(monkeypatch, job_env, name, value):
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(pipeline, "run_review", fake_run_review([]))
    assert entrypoint.main() == entrypoint.EXIT_PERMANENT
    assert name in termination(job_env)


def test_an_unwritable_reports_volume_fails_first_not_last(monkeypatch,
                                                           job_env):
    not_a_dir = job_env / "reports-is-a-file"
    not_a_dir.write_text("", encoding="utf-8")
    monkeypatch.setenv("REVIEW_OUTPUT_DIR", str(not_a_dir))
    called = []
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(called))
    assert entrypoint.main() == entrypoint.EXIT_PERMANENT
    assert "not writable" in termination(job_env) and not called


@pytest.mark.parametrize("message", [
    "Not a valid GitHub repository URL: 'https://gitlab.com/x/y'.",
    "git clone failed: remote: Repository not found.\nfatal: repository "
    "'https://github.com/o/r/' not found",
    "git clone failed: fatal: Authentication failed for 'https://github.com/o/r/'",
    "git clone failed: warning: Could not find remote branch nope to clone.\n"
    "fatal: Remote branch nope not found in upstream origin",
    "No reviewable code files found (check extensions filter).",
])
def test_bad_url_token_or_branch_is_permanent(monkeypatch, job_env,
                                              output_dir, message):
    monkeypatch.setattr(pipeline, "run_review",
                        fake_run_review([], raises=IngestError(message)))
    assert entrypoint.main() == entrypoint.EXIT_PERMANENT


# ---------------- retryable failures: exit 1 ----------------

@pytest.mark.parametrize("exc", [
    LLMUnavailableError("cannot reach the model at http://llm.invalid"),
    IngestError("git clone failed: fatal: unable to access "
                "'https://github.com/o/r/': Could not resolve host: github.com"),
    # A timeout wins over "not found" quoted in its partial output.
    IngestError("git timed out after 300s: git clone ...\noutput so far:\n"
                "remote: Repository not found"),
    IngestError("git clone failed: error: RPC failed; HTTP 503"),
    RuntimeError("something nobody expected"),
    OSError(28, "No space left on device"),
])
def test_technical_failures_are_retryable(monkeypatch, job_env, output_dir,
                                          exc):
    monkeypatch.setattr(pipeline, "run_review",
                        fake_run_review([], raises=exc))
    assert entrypoint.main() == entrypoint.EXIT_RETRYABLE
    assert termination(job_env).startswith("retryable:")


def test_exit_0_needs_the_report_on_disk(monkeypatch, job_env, output_dir):
    monkeypatch.setattr(pipeline, "run_review",
                        fake_run_review([], write=False))
    assert entrypoint.main() == entrypoint.EXIT_RETRYABLE
    assert "missing" in termination(job_env)


def test_sigterm_is_retryable(monkeypatch, job_env, output_dir):
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(
        [], raises=entrypoint.Terminated("received SIGTERM")))
    assert entrypoint.main() == entrypoint.EXIT_RETRYABLE
    assert "SIGTERM" in termination(job_env)


def test_an_unexpected_failure_logs_its_traceback(monkeypatch, job_env,
                                                  output_dir, caplog):
    monkeypatch.setattr(pipeline, "run_review",
                        fake_run_review([], raises=KeyError("surprise")))
    with caplog.at_level(logging.INFO):
        assert entrypoint.main() == 1
    assert "Traceback" in caplog.text
    assert "Traceback" not in termination(job_env)   # Pod status: one line


# ---------------- the real pipeline: crash, retry, resume ----------------

def test_a_retry_with_the_same_review_id_resumes_the_checkpoint(
        monkeypatch, job_env, output_dir):
    """What the contract's REVIEW_ID rule exists for, end to end.

    Attempt 1: the model dies after two files -> exit 1, and
    <id>.partial.json is left on the reports volume. Attempt 2 (a new Pod
    in Kubernetes, a second main() here) with the same REVIEW_ID -> exit 0,
    and only the files attempt 1 did not finish are sent to the model.
    """
    from code_review_mcp import review as review_mod
    from test_dummy_repo import dummy_manifest

    monkeypatch.setenv("MODE", "deep")
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())
    calls = []

    def dying(client, prompt, path, *args, **kwargs):
        calls.append(path)
        if len(calls) == 3:
            raise LLMUnavailableError("model crashed mid-run")
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", dying)
    assert entrypoint.main() == entrypoint.EXIT_RETRYABLE
    checkpoint = output_dir / "rev-001.partial.json"
    assert checkpoint.is_file()
    assert "crashed" in termination(job_env)

    # The retry: a fresh environment, exactly as a new Pod would get it.
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    retried = []

    def healthy(client, prompt, path, *args, **kwargs):
        retried.append(path)
        return {"file": path, "summary": "recovered", "issues": [], "score": 9}

    monkeypatch.setattr(review_mod, "review_chunk", healthy)
    assert entrypoint.main() == entrypoint.EXIT_OK
    report = json.loads((output_dir / "rev-001.json").read_text("utf-8"))
    assert report["resumed"] is True
    assert retried == ["app/main.py", "app/storage.py", "web/login.js"]
    assert (output_dir / "rev-001.md").is_file()
    assert not checkpoint.exists()
