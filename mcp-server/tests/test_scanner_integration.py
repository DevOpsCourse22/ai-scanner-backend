"""The deterministic scanner tier runs inside the pipeline, over the clone.

Track 3 ships `repo_scanner` (Semgrep + Gitleaks + Trivy, normalised into the
findings format this pipeline already ingests). Running it here rather than
in a caller means the repository is cloned ONCE — a second clone would double
the time and put someone else's code on disk twice, against ADR-001.

The clone only exists inside ingest_repository, which deletes it in a finally
block, so the scan has to happen through the on_clone hook. These tests pin
that, and pin that the review still runs when the scanner is absent, off, or
broken — it is an optional package, not a hard dependency.
"""

import json
import sys
import types

import pytest

from code_review_mcp import pipeline
from code_review_mcp import repo_ingest


@pytest.fixture
def fake_scanner(monkeypatch):
    """Stand in for the Track 3 `repo_scanner` package.

    Records the directory it was given so a test can prove the scan saw a
    real clone that still existed at the time.
    """
    calls = {"scanned": [], "existed": []}

    def scan_repository(path: str):
        from pathlib import Path
        calls["scanned"].append(path)
        calls["existed"].append(Path(path).is_dir())
        return {"findings": [
            {"path": "app.py", "line": 2, "severity": "high",
             "rule": "python.lang.security.audit.eval-detected",
             "description": "eval() on user input", "source": "semgrep"},
        ]}

    def write_findings_file(doc, out_path):
        from pathlib import Path
        Path(out_path).write_text(json.dumps(doc), encoding="utf-8")
        calls["written"] = str(out_path)

    module = types.ModuleType("repo_scanner")
    module.scan_repository = scan_repository
    module.write_findings_file = write_findings_file
    monkeypatch.setitem(sys.modules, "repo_scanner", module)
    return calls


def _hook(tmp_path, monkeypatch, name="R.json", enabled=True):
    monkeypatch.setattr(pipeline.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(pipeline.settings, "run_scanner", enabled)
    meta = {}
    out = pipeline._resolve_output(name).with_suffix(".findings.json")
    return pipeline._scanner_hook(out, meta, lambda *a, **k: None), meta, out


# ---------- the hook itself ----------

def test_hook_scans_and_writes_the_findings_file(tmp_path, monkeypatch,
                                                 fake_scanner):
    hook, meta, out = _hook(tmp_path, monkeypatch)
    assert hook is not None

    clone = tmp_path / "clone"
    clone.mkdir()
    hook(clone)

    assert fake_scanner["scanned"] == [str(clone)]
    assert fake_scanner["existed"] == [True]     # scanned a real directory
    assert meta["ran"] is True
    assert out.is_file()
    assert json.loads(out.read_text(encoding="utf-8"))["findings"][0]["line"] == 2


def test_no_hook_when_the_scanner_is_not_installed(tmp_path, monkeypatch):
    """This component must keep working standalone."""
    monkeypatch.setitem(sys.modules, "repo_scanner", None)
    hook, meta, _ = _hook(tmp_path, monkeypatch)
    assert hook is None
    assert "not installed" in meta["reason"]


def test_no_hook_when_switched_off(tmp_path, monkeypatch, fake_scanner):
    hook, meta, _ = _hook(tmp_path, monkeypatch, enabled=False)
    assert hook is None
    assert "disabled" in meta["reason"]


def test_a_broken_scanner_does_not_kill_the_review(tmp_path, monkeypatch):
    """The AI review is still worth running without deterministic findings —
    but the reason is recorded, not swallowed."""
    module = types.ModuleType("repo_scanner")
    module.scan_repository = lambda p: (_ for _ in ()).throw(
        RuntimeError("semgrep binary not found"))
    module.write_findings_file = lambda d, o: None
    monkeypatch.setitem(sys.modules, "repo_scanner", module)

    hook, meta, out = _hook(tmp_path, monkeypatch)
    hook(tmp_path)                                   # must not raise

    assert not meta.get("ran")
    assert "semgrep binary not found" in meta["reason"]
    assert not out.exists()


# ---------- the hook runs while the clone exists ----------

def test_ingest_calls_the_hook_before_deleting_the_clone(tmp_path, monkeypatch):
    """ingest_repository removes the clone in a finally block, so on_clone is
    the ONLY window in which the tree is on disk."""
    seen = {}

    def fake_clone(url, dest, branch=None, token=None):
        dest.mkdir(parents=True)
        (dest / "app.py").write_text("eval(input())\n", encoding="utf-8")
        return "c0ffee"

    monkeypatch.setattr(repo_ingest, "clone_repo", fake_clone)

    def on_clone(clone_dir):
        seen["path"] = clone_dir
        seen["existed"] = clone_dir.is_dir()
        seen["files"] = sorted(p.name for p in clone_dir.iterdir())

    manifest = repo_ingest.ingest_repository(
        "https://github.com/o/r", on_clone=on_clone)

    assert seen["existed"] is True
    assert seen["files"] == ["app.py"]
    assert manifest["file_count"] == 1
    # ...and the clone is gone afterwards. Ephemeral processing still holds.
    assert not seen["path"].exists()


def test_the_clone_is_removed_even_if_the_hook_raises(tmp_path, monkeypatch):
    def fake_clone(url, dest, branch=None, token=None):
        dest.mkdir(parents=True)
        (dest / "a.py").write_text("x = 1\n", encoding="utf-8")
        return "c0ffee"

    monkeypatch.setattr(repo_ingest, "clone_repo", fake_clone)
    captured = {}

    def boom(clone_dir):
        captured["dir"] = clone_dir
        raise RuntimeError("scanner exploded")

    with pytest.raises(RuntimeError, match="scanner exploded"):
        repo_ingest.ingest_repository("https://github.com/o/r", on_clone=boom)
    assert not captured["dir"].exists()          # no repo left behind


# ---------- end to end through run_review ----------

def _stub_review(monkeypatch, captured):
    def fake_review(manifest, prompt, progress=None, mode="brief", **kwargs):
        captured["static_map"] = kwargs.get("static_map")
        return {"repo_url": manifest["repo_url"], "commit": "c0ffee",
                "model": "m", "generated_at": "now", "mode": mode,
                "stats": {"files_reviewed": 1, "files_failed": 0,
                          "files_skipped": 0, "issues_total": 0,
                          "issues_by_severity": {}, "average_score": 8},
                "reviews": [{"file": "app.py", "summary": "ok", "score": 8,
                             "issues": []}],
                "failures": [], "skipped": []}
    monkeypatch.setattr(pipeline, "review_manifest", fake_review)


def _stub_clone(monkeypatch):
    def fake_clone(url, dest, branch=None, token=None):
        dest.mkdir(parents=True)
        (dest / "app.py").write_text("eval(input())\n", encoding="utf-8")
        return "c0ffee"
    monkeypatch.setattr(repo_ingest, "clone_repo", fake_clone)


def test_run_review_scans_automatically_and_feeds_the_findings_in(
        tmp_path, monkeypatch, fake_scanner):
    """The whole point: no manual clone, no manual repo-scan, no filename to
    type. The findings reach the model on their own."""
    monkeypatch.setattr(pipeline.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(pipeline.settings, "run_scanner", True)
    _stub_clone(monkeypatch)
    captured = {}
    _stub_review(monkeypatch, captured)

    pipeline.run_review("https://github.com/o/r", "prompt", "R.json")

    assert fake_scanner["existed"] == [True]
    assert (tmp_path / "R.findings.json").is_file()
    # The scanner's finding was matched to the manifest and handed to review.
    assert captured["static_map"]["app.py"][0]["rule"].endswith("eval-detected")


def test_an_explicit_findings_file_overrides_the_automatic_scan(
        tmp_path, monkeypatch, fake_scanner):
    """A caller who supplies findings is not racing an auto-scan."""
    monkeypatch.setattr(pipeline.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(pipeline.settings, "run_scanner", True)
    _stub_clone(monkeypatch)
    (tmp_path / "mine.json").write_text(json.dumps({"findings": [
        {"path": "app.py", "line": 1, "severity": "low", "rule": "hand-made",
         "description": "supplied by the caller", "source": "manual"}]}),
        encoding="utf-8")
    captured = {}
    _stub_review(monkeypatch, captured)

    pipeline.run_review("https://github.com/o/r", "prompt", "R.json",
                        findings_file="mine.json")

    assert fake_scanner["scanned"] == []                 # never ran
    assert not (tmp_path / "R.findings.json").exists()
    assert captured["static_map"]["app.py"][0]["rule"] == "hand-made"


def test_review_runs_normally_with_no_scanner_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline.settings, "output_dir", str(tmp_path))
    monkeypatch.setitem(sys.modules, "repo_scanner", None)
    _stub_clone(monkeypatch)
    captured = {}
    _stub_review(monkeypatch, captured)

    report = pipeline.run_review("https://github.com/o/r", "prompt", "R.json")

    assert report["stats"]["files_reviewed"] == 1
    assert not captured["static_map"]


# ---------- the private-repo regression they told us to check ----------

def test_a_token_reaches_the_clone(monkeypatch):
    """Regression: run_review passed token= to ingest_repository, which had no
    such parameter, so EVERY private-repo review died with
    `unexpected keyword argument 'token'` before cloning anything."""
    got = {}

    def fake_clone(url, dest, branch=None, token=None):
        got["token"] = token
        dest.mkdir(parents=True)
        (dest / "a.py").write_text("x = 1\n", encoding="utf-8")
        return "c0ffee"

    monkeypatch.setattr(repo_ingest, "clone_repo", fake_clone)
    repo_ingest.ingest_repository("https://github.com/o/r",
                                  token="ghp_perRequest")
    assert got["token"] == "ghp_perRequest"


def test_run_review_hands_its_token_down_to_the_clone(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline.settings, "output_dir", str(tmp_path))
    monkeypatch.setitem(sys.modules, "repo_scanner", None)
    got = {}

    def fake_clone(url, dest, branch=None, token=None):
        got["token"] = token
        dest.mkdir(parents=True)
        (dest / "a.py").write_text("x = 1\n", encoding="utf-8")
        return "c0ffee"

    monkeypatch.setattr(repo_ingest, "clone_repo", fake_clone)
    _stub_review(monkeypatch, {})

    pipeline.run_review("https://github.com/o/r", "prompt", "R.json",
                        github_token="ghp_fromTheApi")

    assert got["token"] == "ghp_fromTheApi"


# ---------- the guard that would have caught the token bug ----------

def test_run_review_calls_ingest_with_arguments_it_actually_accepts():
    """Bind the real signature to the call run_review makes.

    `token=` sat in that call for months against an ingest_repository with no
    such parameter. Public reviews passed because the kwarg was only sent
    when a token existed, so nothing exercised it until a private review did
    — and the failure surfaced as a TypeError at clone time, not as a test.
    Both kwargs are unconditional now, and this binds them.
    """
    import inspect
    sig = inspect.signature(repo_ingest.ingest_repository)
    # Exactly how pipeline.run_review calls it.
    sig.bind("https://github.com/o/r", None, None, token=None, on_clone=None)


def test_every_ingest_fake_in_the_suite_matches_the_real_signature():
    """A fake that accepts fewer arguments than the real function turns a
    signature mismatch into a green test — which is what happened."""
    import inspect
    import pathlib
    import re

    real = inspect.signature(repo_ingest.ingest_repository)
    tests_dir = pathlib.Path(__file__).parent
    offenders = []
    for path in tests_dir.glob("test_*.py"):
        text = path.read_text(encoding="utf-8")
        if "ingest_repository" not in text:
            continue
        for match in re.finditer(
                r"(?:def|lambda)\s*\w*\s*\(([^)]*)\)\s*(?::|->)", text):
            params = match.group(1)
            if "repo_url" in params and "branch" in params:
                if "**" not in params:
                    offenders.append(f"{path.name}: ({params})")
    assert not offenders, (
        "these ingest fakes cannot absorb the real signature: "
        + "; ".join(offenders))
    # And the real thing still takes what the pipeline sends.
    real.bind("u", None, None, token=None, on_clone=None)


# ---------- a resume reuses the scan of the same commit ----------

def _git_clone_dir(tmp_path, name="clone"):
    """A real one-commit repository, standing in for a fresh clone."""
    import subprocess
    clone = tmp_path / name
    clone.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(clone), *a],  # noqa: E731
                                    check=True, capture_output=True)
    run("init", "-q")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
        "--allow-empty", "-m", "one")
    head = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    return clone, run, head


def _stamped_hook(tmp_path, monkeypatch, repo="https://github.com/o/r"):
    monkeypatch.setattr(pipeline.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(pipeline.settings, "run_scanner", True)
    meta, seen = {}, []
    out = pipeline._resolve_output("R.json").with_suffix(".findings.json")
    hook = pipeline._scanner_hook(out, meta,
                                  lambda s, **k: seen.append((s, k)), repo)
    return hook, meta, out, seen


def test_the_scan_is_stamped_with_repo_and_commit(tmp_path, monkeypatch,
                                                  fake_scanner):
    clone, _, head = _git_clone_dir(tmp_path)
    hook, meta, out, _ = _stamped_hook(tmp_path, monkeypatch)
    hook(clone)
    ctx = json.loads(out.read_text(encoding="utf-8"))["scan_context"]
    assert ctx["commit"] == head
    assert ctx["repo_url"] == "https://github.com/o/r"


def test_a_resume_on_the_same_commit_skips_the_scanners(tmp_path, monkeypatch,
                                                         fake_scanner):
    clone, _, _ = _git_clone_dir(tmp_path)
    first, _, _, _ = _stamped_hook(tmp_path, monkeypatch)
    first(clone)
    assert len(fake_scanner["scanned"]) == 1

    again, meta, out, seen = _stamped_hook(tmp_path, monkeypatch)
    again(clone)
    assert len(fake_scanner["scanned"]) == 1          # not scanned again
    assert meta["ran"] is True and meta["reused_from"]
    assert ("scanning", {"scan_reused": True}) in seen
    # The reused file still feeds the review like a fresh one.
    static_map, _ = pipeline.load_findings_file(out)
    assert "app.py" in static_map


def test_a_new_commit_is_scanned_again(tmp_path, monkeypatch, fake_scanner):
    clone, run, _ = _git_clone_dir(tmp_path)
    first, _, _, _ = _stamped_hook(tmp_path, monkeypatch)
    first(clone)
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
        "--allow-empty", "-m", "two")
    again, meta, _, _ = _stamped_hook(tmp_path, monkeypatch)
    again(clone)
    assert len(fake_scanner["scanned"]) == 2
    assert "reused_from" not in meta


def test_another_repository_is_scanned_again(tmp_path, monkeypatch,
                                             fake_scanner):
    clone, _, _ = _git_clone_dir(tmp_path)
    first, _, _, _ = _stamped_hook(tmp_path, monkeypatch)
    first(clone)
    other, _, _, _ = _stamped_hook(tmp_path, monkeypatch,
                                   repo="https://github.com/o/other")
    other(clone)
    assert len(fake_scanner["scanned"]) == 2


def test_an_unstamped_findings_file_is_not_trusted(tmp_path, monkeypatch,
                                                   fake_scanner):
    clone, _, _ = _git_clone_dir(tmp_path)
    hook, _, out, _ = _stamped_hook(tmp_path, monkeypatch)
    out.write_text(json.dumps({"findings": []}), encoding="utf-8")
    hook(clone)
    assert len(fake_scanner["scanned"]) == 1
