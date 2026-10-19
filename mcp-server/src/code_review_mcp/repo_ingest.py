"""Stage 1: clone a GitHub repo and convert its code into a pure JSON manifest.

The manifest shape:
{
  "repo_url": "...",
  "commit": "abc123...",
  "file_count": 12,
  "files": [
    {"path": "src/app.py", "language": "python", "size_bytes": 1234, "content": "..."},
    ...
  ],
  "skipped": [{"path": "...", "reason": "..."}],
  "excluded": {"count": 12, "by_type": {".png": 10, ".lock": 2},
               "examples": ["docs/logo.png", ...]}
}

"skipped" is a reviewable file the walk had to give up on (too large,
not UTF-8). "excluded" is a file whose type is not reviewed at all —
counted rather than dropped silently, so coverage can be stated honestly.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .config import (DEFAULT_EXTENSIONS, SKIP_DIRS, classify_file,
                     looks_generated, settings)

logger = logging.getLogger(__name__)

_GITHUB_URL_RE = re.compile(
    r"^https?://(www\.)?github\.com/[\w.\-]+/[\w.\-]+(\.git)?/?$"
)

# The username half of HTTPS token auth. Not a secret: GitHub accepts any
# username when the password is a PAT, and putting it in the URL means git
# only ever asks for the password (which GIT_ASKPASS supplies).
_TOKEN_USERNAME = "x-access-token"

# Env var the askpass helper reads the token from. The token lives in the
# child process environment only — never in a command line or on disk.
_ASKPASS_TOKEN_VAR = "CODE_REVIEW_GIT_TOKEN"

# Disable any inherited credential helper (Git Credential Manager on
# Windows, osxkeychain, ...) for the commands we run. Three reasons:
# 1) a helper is consulted BEFORE GIT_ASKPASS and, on Windows, tries to open
#    a GUI prompt — the console-less-hang class this server already fights;
# 2) it emits "Cannot prompt because user interactivity has been disabled",
#    which misdirects users away from the real cause (their token);
# 3) authentication stays EXPLICIT: the only credential is the configured
#    GITHUB_TOKEN, so behaviour is identical on every machine and in the
#    container, instead of silently depending on ambient host credentials.
_GIT_NO_HELPER = ["-c", "credential.helper="]


class IngestError(RuntimeError):
    """Raised when cloning or reading the repository fails."""


def validate_repo_url(repo_url: str) -> str:
    url = repo_url.strip().rstrip("/")
    if not _GITHUB_URL_RE.match(url):
        # SSH first: "git@github.com:owner/repo" also contains an "@" and
        # would otherwise be misdiagnosed as a credential in the URL.
        if url.startswith(("git@", "ssh://")):
            raise IngestError(
                f"SSH URLs are not supported: {repo_url!r}. Use the HTTPS "
                "form https://github.com/<owner>/<repo>; private "
                "repositories authenticate with the GITHUB_TOKEN "
                "environment variable."
            )
        # Credentials embedded in the URL would be recorded in the report and
        # printed in git's error output; refuse and point at the env var.
        if "@" in url and "github.com" in url:
            raise IngestError(
                "Do not put credentials in the repository URL (they would "
                "be written into the report and the logs). Pass a plain "
                "https://github.com/<owner>/<repo> URL and set the "
                "GITHUB_TOKEN environment variable on the server instead."
            )
        raise IngestError(
            f"Not a valid GitHub repository URL: {repo_url!r}. "
            "Expected https://github.com/<owner>/<repo>"
        )
    return url


def _redact(text: str, token: str | None = None) -> str:
    """Remove any credential from text before it reaches a log or exception.

    Scrubs both the per-request token (HTTP API callers supply their own)
    and the server-wide one, so neither can leak through either path.
    """
    for secret in (token, settings.github_token):
        if secret and secret in text:
            text = text.replace(secret, "***REDACTED***")
    return text


def _write_askpass(directory: Path) -> Path:
    """Write the helper git calls to obtain the password (our token).

    The script itself contains NO secret: it echoes whatever is in the
    _ASKPASS_TOKEN_VAR environment variable, which is set only for the git
    child process. This is what keeps the token out of the process list —
    git is invoked with no credential in its arguments at all.
    """
    if sys.platform == "win32":
        script = directory / "askpass.bat"
        script.write_text(
            f"@echo off\r\necho %{_ASKPASS_TOKEN_VAR}%\r\n", encoding="ascii"
        )
    else:
        script = directory / "askpass.sh"
        script.write_text(
            f'#!/bin/sh\nprintf \'%s\\n\' "${_ASKPASS_TOKEN_VAR}"\n',
            encoding="ascii",
        )
        script.chmod(0o700)
    return script


def _auth_context(url: str, work_dir: Path,
                  token: str | None = None) -> tuple[str, dict[str, str]]:
    """Return (url_for_git, extra_env) for cloning.

    Without a token nothing changes — public clones behave exactly as before.
    With one, the URL gains the (non-secret) username so git skips the
    username prompt, and GIT_ASKPASS + the token env var supply the password.

    token overrides the server-wide GITHUB_TOKEN for this call only (the HTTP
    API passes a per-review credential); it is never written anywhere.
    """
    token = token or settings.github_token
    if not token:
        return url, {}
    # Token auth requires TLS; GitHub would redirect anyway, but never send
    # a credential to a plaintext endpoint.
    if url.startswith("http://"):
        url = "https://" + url[len("http://"):]
    auth_url = url.replace("https://", f"https://{_TOKEN_USERNAME}@", 1)
    askpass = _write_askpass(work_dir)
    return auth_url, {
        "GIT_ASKPASS": askpass.as_posix(),
        _ASKPASS_TOKEN_VAR: token,
    }


def _on_rm_error(func, path, exc_info):  # noqa: ANN001 - shutil callback signature
    """Make a best effort to remove one file the tree walk could not.

    Two distinct Windows failures land here:

    * read-only — .git objects are written read-only; clear the bit.
    * SHARING VIOLATION (WinError 32) — the file is still open. git for
      Windows runs a `git` -> `git.exe` chain and the inner process can
      briefly outlive proc.wait() while holding the inherited handle on
      git_output.log. Nothing is wrong; the handle just has not been
      released yet, so a short retry succeeds where an immediate one does
      not.
    """
    try:
        Path(path).chmod(stat.S_IWRITE)
    except OSError:
        pass
    for delay in (0, 0.1, 0.3, 0.6):
        if delay:
            time.sleep(delay)
        try:
            func(path)
            return
        except PermissionError:
            continue
    func(path)          # out of retries: let the caller see the real error


def _kill_tree(pid: int) -> None:
    """Kill a process and all of its descendants.

    Plain proc.kill() only kills the direct child; Git for Windows runs a
    wrapper git -> git.exe chain, and an orphaned inner git.exe keeps the
    output handles open, blocking communicate() forever.
    """
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    else:
        import signal

        os.kill(pid, signal.SIGKILL)


def _run_git(cmd: list[str], timeout: float, log_dir: Path,
             env_extra: dict[str, str] | None = None,
             token: str | None = None) -> tuple[int, str]:
    """Run a git command hardened for console-less MCP host contexts.

    MCP hosts spawn this server with CREATE_NO_WINDOW and pipe-based stdio.
    Git for Windows (MSYS2) can deadlock in that situation when it inherits
    the protocol pipes as its stdio, so:
    - stdin comes from NUL (never the MCP protocol pipe),
    - stdout/stderr go to a temp file (no pipe buffers to deadlock on),
    - interactive terminal credential prompts are disabled entirely (an
      askpass helper in env_extra is still honoured, and cannot hang),
    - on timeout the whole process tree is killed, not just the wrapper.

    env_extra carries the credential environment for private clones. It is
    never logged, and the command line is logged redacted regardless.
    """
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    if env_extra:
        env.update(env_extra)
    log_path = log_dir / "git_output.log"
    logger.info("running: %s", _redact(" ".join(cmd), token))
    with open(log_path, "w+b") as log:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc.pid)
            proc.wait(timeout=10)
            log.flush()
            log.seek(0)
            output = log.read().decode("utf-8", errors="replace")
            raise IngestError(_redact(
                f"git timed out after {timeout}s: {' '.join(cmd[:2])} ...\n"
                f"output so far:\n{output[-2000:]}", token
            ))
        log.seek(0)
        output = log.read().decode("utf-8", errors="replace")
    logger.info("git finished rc=%s", returncode)
    return returncode, _redact(output, token)


_AUTH_FAILURE_MARKERS = (
    "not found", "authentication failed", "invalid username",
    "could not read username", "could not read password", "403",
    "terminal prompts disabled",
)


def _access_hint(output: str, token: str | None = None) -> str:
    """Explain an access failure, including the private-repo case.

    GitHub answers "repository not found" (not 403) for a private repo when
    the caller is unauthenticated, which reads as a typo to most users. Say
    what is actually going on — and whether a token was even configured.
    Reports token PRESENCE only; never the value.
    """
    if not any(m in output.lower() for m in _AUTH_FAILURE_MARKERS):
        return ""
    if token or settings.github_token:
        return (
            "\nA GITHUB_TOKEN is configured, so the repository is reachable "
            "only if that token grants access. Check that it: has the 'repo' "
            "scope (classic PAT) or read access to this repository "
            "(fine-grained PAT), has not expired, and — for a repository "
            "owned by an organization with SAML SSO — has been authorized "
            "for that organization."
        )
    return (
        "\nNo GITHUB_TOKEN is configured, so this clone was anonymous. "
        "GitHub reports PRIVATE repositories as 'not found' to anonymous "
        "callers, so this may be a private repo rather than a wrong URL. To "
        "scan a private repository, set the GITHUB_TOKEN environment "
        "variable on the server (Docker: add -e GITHUB_TOKEN to the run "
        "args) and try again."
    )


# A full commit SHA. Only the full form: GitHub serves a fetch by SHA only
# for the complete 40 hex characters, and an abbreviation could be ambiguous.
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def clone_repo(repo_url: str, dest: Path, branch: str | None = None,
               token: str | None = None, commit: str | None = None) -> str:
    """Shallow-clone the repo into dest. Returns the checked-out commit SHA.

    Private repositories are cloned with `token` (HTTP API, per review) or the
    server-wide GITHUB_TOKEN, handed to git via GIT_ASKPASS so the credential
    never enters the command line.

    `commit` pins the clone to one exact commit instead of the branch's
    current tip. A resumed review needs this: its checkpoint is only reused
    when the commit matches, so resuming a paused review after someone
    pushed to the branch would otherwise silently start over from file 1.
    """
    if commit is not None:
        commit = commit.strip().lower()
        if not _COMMIT_RE.match(commit):
            raise IngestError(
                f"commit must be a full 40-character SHA, got {commit!r}")
    url_for_git, auth_env = _auth_context(repo_url, dest.parent, token)
    cmd = ["git", *_GIT_NO_HELPER, "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url_for_git, str(dest)]
    rc, output = _run_git(cmd, timeout=300, log_dir=dest.parent,
                          env_extra=auth_env, token=token)
    if rc != 0:
        # _run_git already redacts, but redact again here: a credential must
        # never depend on a single chokepoint staying correct.
        raise IngestError(_redact(
            f"git clone failed: {output.strip()[-2000:]}"
            f"{_access_hint(output, token)}", token
        ))
    rc, output = _run_git(
        ["git", "-C", str(dest), "rev-parse", "HEAD"], timeout=30, log_dir=dest.parent
    )
    head = output.strip() if rc == 0 else "unknown"
    if commit and head != commit:
        head = _checkout_commit(dest, commit, auth_env, token)
    return head


def _checkout_commit(dest: Path, commit: str, auth_env: dict[str, str],
                     token: str | None) -> str:
    """Move a shallow clone to `commit`: fetch just that commit, check it out.

    Fails loudly when the commit is gone (force-pushed away, wrong repo)
    rather than quietly reviewing the branch tip under the old commit's
    name - a resume that cannot find its commit must say so.
    """
    rc, output = _run_git(
        ["git", *_GIT_NO_HELPER, "-C", str(dest), "fetch", "--depth", "1",
         "origin", commit],
        timeout=300, log_dir=dest.parent, env_extra=auth_env, token=token)
    if rc != 0:
        raise IngestError(_redact(
            f"commit {commit} could not be fetched (was it force-pushed "
            f"away?): {output.strip()[-1000:]}", token))
    rc, output = _run_git(
        ["git", "-C", str(dest), "checkout", "--quiet", "--detach", commit],
        timeout=60, log_dir=dest.parent)
    if rc != 0:
        raise IngestError(_redact(
            f"git checkout {commit} failed: {output.strip()[-1000:]}", token))
    rc, output = _run_git(
        ["git", "-C", str(dest), "rev-parse", "HEAD"], timeout=30,
        log_dir=dest.parent)
    head = output.strip() if rc == 0 else "unknown"
    if head != commit:
        raise IngestError(f"checked out {head}, expected {commit}")
    return head


def check_access(repo_url: str, branch: str | None = None,
                 token: str | None = None) -> dict[str, Any]:
    """Can the server reach this repository? Cheap: ls-remote, no clone.

    Worth running before a long review of a private repository, so a bad or
    unauthorized token costs seconds instead of failing an hour in.

    `token` overrides the server-wide GITHUB_TOKEN for this call only, exactly
    as it does for clone_repo — otherwise an HTTP caller could not pre-check
    the credential it is about to review with. It is redacted from every
    message and reported only as presence.
    """
    url = validate_repo_url(repo_url)
    tmp = Path(tempfile.mkdtemp(prefix="code_review_access_"))
    try:
        url_for_git, auth_env = _auth_context(url, tmp, token)
        cmd = ["git", *_GIT_NO_HELPER, "ls-remote", "--heads", url_for_git]
        if branch:
            cmd.append(branch)
        rc, output = _run_git(cmd, timeout=60, log_dir=tmp,
                              env_extra=auth_env, token=token)
        effective = token or settings.github_token
        result: dict[str, Any] = {
            "repo_url": url,
            "authenticated": bool(effective),
            "token_source": ("request" if token
                             else "GITHUB_TOKEN/GH_TOKEN environment variable"
                             if settings.github_token else "none (anonymous)"),
        }
        if rc != 0:
            result["status"] = "no_access"
            result["error"] = _redact(
                output.strip()[-600:] + _access_hint(output, token), token)
            return result
        refs = [line.split("\t")[-1] for line in output.splitlines()
                if "\t" in line]
        result["status"] = "ok"
        result["branches_found"] = len(refs)
        result["sample_branches"] = [r.removeprefix("refs/heads/")
                                     for r in refs[:10]]
        if branch:
            result["branch"] = branch
            result["branch_exists"] = bool(refs)
        result["note"] = ("Repository is reachable"
                          + (" using the supplied token." if token
                             else " using the configured token."
                             if settings.github_token
                             else " anonymously (it is public)."))
        return result
    finally:
        shutil.rmtree(tmp, onerror=_on_rm_error)


def _symlink_reason(path: Path, root_real: Path) -> str:
    """Why a link was not read, naming where it points.

    The target is the repository's own text, not a secret, and it is the
    part a reader needs: "skipped: symlink" alone would hide an attempt to
    read /proc/self/environ behind the same words as a harmless README link.
    """
    try:
        target = os.readlink(path)[:200]
    except OSError:
        # Not a link itself: a parent directory is one, and it leads out.
        return "inside a symlinked directory that leads outside the repository; not read"
    resolved = path.resolve()
    if not resolved.exists():
        return f"broken symlink (-> {target}); not read"
    if resolved.is_relative_to(root_real):
        return f"symlink to a path inside the repository (-> {target}); not read twice"
    return f"symlink pointing outside the repository (-> {target}); not read"


def collect_files(root: Path, extensions: set[str] | None = None) -> dict[str, Any]:
    """Walk the tree and build the files/skipped/excluded parts of the manifest.

    Files whose type is not reviewable are counted into `excluded` rather
    than dropped in silence. Without that record a report says
    "files reviewed: 2, skipped: 0" for a repository of 57 files and reads
    like full coverage.
    """
    exts = extensions or DEFAULT_EXTENSIONS
    by_name = extensions is None
    files: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    excluded_by_type: Counter[str] = Counter()
    excluded_examples: list[str] = []

    root_real = root.resolve()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        # Before is_file(), which follows links - and so does read_text().
        # A repository can ship `leak.py -> /proc/self/environ` or a link
        # to another review's report on /reports, and both would be read
        # here as if they were its own source. Nothing from the repository
        # runs: OUR read follows the link, with this process's permissions.
        # Links are recorded, never read; the scanner tier reports the ones
        # that leave the repository as findings (repo_scanner.symlinks).
        if path.is_symlink() or not path.resolve().is_relative_to(root_real):
            skipped.append({"path": rel.as_posix(),
                            "reason": _symlink_reason(path, root_real)})
            continue
        if not path.is_file():
            continue
        rel_str = rel.as_posix()
        language = classify_file(path.name, exts, by_name)
        if language is None:
            excluded_by_type[path.suffix.lower() or path.name.lower()] += 1
            if len(excluded_examples) < 25:
                excluded_examples.append(rel_str)
            continue
        size = path.stat().st_size
        if size > settings.max_file_bytes:
            skipped.append({"path": rel_str, "reason": f"too large ({size} bytes)"})
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            skipped.append({"path": rel_str, "reason": "not valid UTF-8 (binary?)"})
            continue
        # Minified bundles and notebook exports: hours of review time for
        # nothing a reader can act on. Recorded in `skipped`, never dropped
        # in silence — the report has to say what it did not read.
        if settings.skip_generated:
            generated = looks_generated(path.name, content)
            if generated:
                skipped.append({"path": rel_str, "reason": generated})
                continue
        files.append({
            "path": rel_str,
            "language": language,
            "size_bytes": size,
            "content": content,
        })
        if len(files) >= settings.max_files:
            skipped.append({"path": "...", "reason": f"file cap ({settings.max_files}) reached"})
            break

    return {
        "files": files,
        "skipped": skipped,
        "excluded": {
            "count": sum(excluded_by_type.values()),
            "by_type": dict(excluded_by_type.most_common()),
            "examples": excluded_examples,
        },
    }


def ingest_repository(
    repo_url: str,
    branch: str | None = None,
    extensions: list[str] | None = None,
    token: str | None = None,
    on_clone: Callable[[Path], None] | None = None,
    commit: str | None = None,
) -> dict[str, Any]:
    """Clone + convert to the pure-JSON manifest. Cleans up the clone afterwards.

    token authenticates a private clone for THIS call only, overriding the
    server-wide GITHUB_TOKEN. It reaches git through GIT_ASKPASS, so it
    appears in no command line, URL or log.

    on_clone, if given, is called with the clone directory WHILE IT STILL
    EXISTS — after checkout, before the manifest is built and before the
    tree is deleted. That is the only safe window for a tool that needs the
    files on disk (the deterministic scanner tier): this function removes
    the clone in a finally block, so there is no directory left to scan by
    the time it returns. Exceptions propagate; the clone is still cleaned
    up, and the caller decides whether a scanner failure is fatal.
    """
    url = validate_repo_url(repo_url)
    exts = {e if e.startswith(".") else f".{e}" for e in extensions} if extensions else None

    tmp = Path(tempfile.mkdtemp(prefix="code_review_mcp_"))
    logger.info("cloning %s into %s", url, tmp)
    try:
        # `commit` only when pinned, so an unpinned review makes exactly the
        # call it always made (tests and callers that stub clone_repo rely
        # on that signature).
        pin = {"commit": commit} if commit else {}
        commit = clone_repo(url, tmp / "repo", branch, token, **pin)
        logger.info("cloned at %s; collecting files", commit[:8])
        if on_clone is not None:
            # Before the manifest filter, so a scanner sees the WHOLE tree —
            # lockfiles, images and config it cares about are not reviewable
            # source and would not survive collect_files.
            logger.info("running on_clone hook over the working tree")
            on_clone(tmp / "repo")
        collected = collect_files(tmp / "repo", exts)
        excluded = collected.get("excluded") or {}
        logger.info("collected %d files (%d skipped, %d not a reviewable type)",
                    len(collected["files"]), len(collected["skipped"]),
                    excluded.get("count", 0))
    finally:
        # Cleanup must never destroy a completed review. The clone is
        # ephemeral by design (ADR-001) and this removes it in every normal
        # case, but if Windows still holds a handle after the retries above,
        # a leftover temp directory is a far smaller problem than throwing
        # away a review that already did all of its work.
        try:
            shutil.rmtree(tmp, onerror=_on_rm_error)
            logger.info("temp clone cleaned up")
        except OSError as exc:
            logger.warning(
                "could not remove the temp clone at %s (%s). The review is "
                "unaffected; delete it manually if it persists.", tmp, exc)

    return {
        "repo_url": url,
        "branch": branch or "default",
        "commit": commit,
        # Provenance, not a secret: whether the clone used a credential.
        "authenticated": bool(settings.github_token),
        "file_count": len(collected["files"]),
        "files": collected["files"],
        "skipped": collected["skipped"],
        "excluded": excluded,
    }


def save_manifest(manifest: dict[str, Any], output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return out
