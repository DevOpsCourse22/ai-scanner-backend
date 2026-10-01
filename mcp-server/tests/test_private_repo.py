"""Tests for private-repository cloning (token auth).

The security contract these lock down comes straight from the project's
threat model ("clone token appears in logs or process list" -> URL
redaction, no argument token, structured errors; validated by *log and
process inspection tests*):

  1. The token NEVER appears in a git command line (process list).
  2. The token NEVER appears in a log record or an exception message.
  3. The token is NEVER a tool argument — it comes only from the server's
     own environment, so it cannot reach the chat transcript.
  4. Credentials embedded in a repo URL are refused outright.
  5. A private repo hit anonymously produces an explanatory hint, not a
     misleading "not found".
"""

import json
import logging

import pytest

from code_review_mcp import repo_ingest
from code_review_mcp.repo_ingest import (
    IngestError, _access_hint, _auth_context, _redact, clone_repo,
    validate_repo_url,
)

FAKE_TOKEN = "ghp_FAKEtoken000111222333444555666777888"
REPO = "https://github.com/owner/private-repo"


@pytest.fixture
def with_token(monkeypatch):
    monkeypatch.setattr(repo_ingest.settings, "github_token", FAKE_TOKEN)
    return FAKE_TOKEN


# ---------- no token: public behaviour is unchanged ----------

def test_no_token_leaves_url_and_env_untouched(monkeypatch, tmp_path):
    monkeypatch.setattr(repo_ingest.settings, "github_token", "")
    url, env = _auth_context(REPO, tmp_path)
    assert url == REPO
    assert env == {}
    assert not list(tmp_path.iterdir())        # no askpass helper written


# ---------- token plumbing ----------

def test_auth_context_puts_username_not_token_in_url(with_token, tmp_path):
    url, env = _auth_context(REPO, tmp_path)
    assert url == "https://x-access-token@github.com/owner/private-repo"
    assert FAKE_TOKEN not in url               # THE point: never in the URL
    assert env["CODE_REVIEW_GIT_TOKEN"] == FAKE_TOKEN
    assert env["GIT_ASKPASS"].endswith(("askpass.sh", "askpass.bat"))


def test_askpass_helper_contains_no_secret(with_token, tmp_path):
    _, env = _auth_context(REPO, tmp_path)
    script = next(tmp_path.iterdir())
    body = script.read_text(encoding="ascii")
    # The helper only dereferences an env var; the token is not on disk.
    assert FAKE_TOKEN not in body
    assert "CODE_REVIEW_GIT_TOKEN" in body


def test_http_is_upgraded_to_https_before_sending_a_credential(with_token,
                                                              tmp_path):
    url, _ = _auth_context("http://github.com/owner/repo", tmp_path)
    assert url.startswith("https://")


# ---------- TM: process-list and log inspection ----------

def test_token_absent_from_git_argv_and_logs(with_token, monkeypatch,
                                             tmp_path, caplog):
    """Process-list + log inspection test mandated by the threat model."""
    calls = []

    def fake_run_git(cmd, timeout, log_dir, env_extra=None, token=None):
        calls.append({"cmd": list(cmd), "env": dict(env_extra or {})})
        return 0, "deadbeef\n"

    monkeypatch.setattr(repo_ingest, "_run_git", fake_run_git)
    with caplog.at_level(logging.INFO, logger=repo_ingest.__name__):
        clone_repo(REPO, tmp_path / "repo")

    # EVERY git invocation must be free of the credential, not just the first.
    for call in calls:
        assert FAKE_TOKEN not in " ".join(call["cmd"])
    clone_call = next(c for c in calls if "clone" in c["cmd"])
    assert "x-access-token@github.com" in " ".join(clone_call["cmd"])
    # The credential travels in the environment only.
    assert clone_call["env"]["CODE_REVIEW_GIT_TOKEN"] == FAKE_TOKEN
    assert all(FAKE_TOKEN not in r.getMessage() for r in caplog.records)


def test_redaction_scrubs_token_from_text(with_token):
    leaked = f"fatal: could not read Password for 'https://x:{FAKE_TOKEN}@x'"
    assert FAKE_TOKEN not in _redact(leaked)
    assert "***REDACTED***" in _redact(leaked)


def test_clone_failure_message_is_redacted(with_token, monkeypatch, tmp_path):
    def failing_git(cmd, timeout, log_dir, env_extra=None, token=None):
        # Simulate git echoing the credential back in an error.
        return 128, f"fatal: Authentication failed using {FAKE_TOKEN}"

    monkeypatch.setattr(repo_ingest, "_run_git", failing_git)
    with pytest.raises(IngestError) as excinfo:
        clone_repo(REPO, tmp_path / "repo")
    assert FAKE_TOKEN not in str(excinfo.value)


# ---------- credentials in the URL are refused ----------

@pytest.mark.parametrize("url", [
    "https://user:ghp_secret@github.com/owner/repo",
    "https://ghp_secret@github.com/owner/repo",
])
def test_credentials_in_url_rejected(url):
    with pytest.raises(IngestError, match="Do not put credentials"):
        validate_repo_url(url)


def test_ssh_url_rejected_with_https_guidance():
    with pytest.raises(IngestError, match="SSH URLs are not supported"):
        validate_repo_url("git@github.com:owner/repo.git")


# ---------- honest diagnosis of private-repo failures ----------

def test_hint_explains_private_repo_when_anonymous(monkeypatch):
    monkeypatch.setattr(repo_ingest.settings, "github_token", "")
    hint = _access_hint("remote: Repository not found.")
    assert "PRIVATE" in hint and "GITHUB_TOKEN" in hint


def test_hint_points_at_scope_and_sso_when_token_present(with_token):
    hint = _access_hint("remote: Repository not found.")
    assert "scope" in hint and "SSO" in hint
    assert FAKE_TOKEN not in hint               # presence only, never value


def test_no_hint_for_unrelated_failures(with_token):
    assert _access_hint("fatal: unable to access: SSL certificate problem") == ""


# ---------- check_access ----------

def test_check_access_reports_success_without_exposing_token(with_token,
                                                             monkeypatch):
    monkeypatch.setattr(
        repo_ingest, "_run_git",
        lambda cmd, timeout, log_dir, env_extra=None, token=None:
        (0, "abc123\trefs/heads/main\ndef456\trefs/heads/dev\n"))
    result = repo_ingest.check_access(REPO)
    assert result["status"] == "ok"
    assert result["authenticated"] is True
    assert result["branches_found"] == 2
    assert result["sample_branches"] == ["main", "dev"]
    assert FAKE_TOKEN not in json.dumps(result)


def test_check_access_reports_no_access_with_hint(monkeypatch):
    monkeypatch.setattr(repo_ingest.settings, "github_token", "")
    monkeypatch.setattr(
        repo_ingest, "_run_git",
        lambda cmd, timeout, log_dir, env_extra=None, token=None:
        (128, "remote: Repository not found."))
    result = repo_ingest.check_access(REPO)
    assert result["status"] == "no_access"
    assert result["authenticated"] is False
    assert "PRIVATE" in result["error"]


def test_check_access_confirms_a_branch(with_token, monkeypatch):
    monkeypatch.setattr(
        repo_ingest, "_run_git",
        lambda cmd, timeout, log_dir, env_extra=None, token=None:
        (0, "abc123\trefs/heads/release\n"))
    result = repo_ingest.check_access(REPO, branch="release")
    assert result["branch_exists"] is True


# ---------- no tool exposes a token argument ----------

def test_no_tool_accepts_a_token_argument():
    """Threat model: 'no argument token'. Guards against a future regression."""
    import inspect

    from code_review_mcp import server

    banned = ("token", "password", "secret", "credential", "passwd", "auth")
    for name in ("start_review", "check_repo_access", "ingest_repository_only",
                 "get_report", "review_repository"):
        params = inspect.signature(getattr(server, name)).parameters
        offenders = [p for p in params if any(b in p.lower() for b in banned)]
        assert not offenders, f"{name} exposes credential argument(s): {offenders}"


def test_manifest_records_auth_provenance_not_the_token(with_token,
                                                        monkeypatch, tmp_path):
    monkeypatch.setattr(repo_ingest, "clone_repo",
                        lambda url, dest, branch=None, token=None: "c0ffee")
    monkeypatch.setattr(repo_ingest, "collect_files",
                        lambda root, exts: {"files": [], "skipped": []})
    manifest = repo_ingest.ingest_repository(REPO)
    assert manifest["authenticated"] is True
    assert manifest["repo_url"] == REPO         # clean URL, no credential
    assert FAKE_TOKEN not in json.dumps(manifest)
