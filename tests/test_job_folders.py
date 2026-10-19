"""Each review Job sees only its own folder of the reports PVC.

A Job runs a stranger's repository. With the whole PVC mounted at /reports,
anything that ran code in the worker (or a link the engine followed, see
mcp-server/tests/test_symlinks.py) could read every other user's report.
Now the Job mounts `.jobs/<review_id>/` with subPath, and review-api copies
what it writes there to the flat files it has always read.
"""

import json
import os
from types import SimpleNamespace

import pytest

from review_api import k8s_jobs
from review_api.k8s_jobs import (KubernetesJobStore, build_job_manifest,
                                 job_dir, prepare_job_dir, sync_job_dir)


def _manifest(review_id="abc"):
    return build_job_manifest(
        k8s_job_name="review-abc-1-f00baa", review_id=review_id,
        repo_url="https://github.com/o/r", mode="brief", system_prompt="p",
        lmstudio_base_url="http://lmstudio:1234/v1")


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if not isinstance(data, str) else data,
                    encoding="utf-8")


def test_the_job_mounts_only_its_own_folder():
    pod = _manifest("rev-1")["spec"]["template"]["spec"]
    (mount,) = [m for m in pod["containers"][0]["volumeMounts"]
                if m["name"] == "reports"]
    assert mount == {"name": "reports", "mountPath": "/reports",
                     "subPath": ".jobs/rev-1"}


def test_prepare_creates_the_folder_and_seeds_the_resume(tmp_path):
    _write(tmp_path / "abc.partial.json", {"reviews": [1]})
    _write(tmp_path / "abc.findings.json", {"findings": []})
    _write(tmp_path / "other.json", {"secret": "someone else's"})
    folder = prepare_job_dir(tmp_path, "abc")
    assert folder == job_dir(tmp_path, "abc") and folder.is_dir()
    assert json.loads((folder / "abc.partial.json").read_text()) == {
        "reviews": [1]}
    assert (folder / "abc.findings.json").is_file()
    # Nothing that belongs to another review, ever.
    assert sorted(p.name for p in folder.iterdir()) == [
        "abc.findings.json", "abc.partial.json"]


def test_prepare_drops_the_previous_attempts_progress_and_error(tmp_path):
    folder = job_dir(tmp_path, "abc")
    _write(folder / "abc.progress.json", {"updated_at": 1})
    _write(folder / "abc.error.json", {"permanent": True})
    prepare_job_dir(tmp_path, "abc")
    assert not (folder / "abc.progress.json").exists()
    assert not (folder / "abc.error.json").exists()


def test_prepare_keeps_a_checkpoint_newer_than_the_flat_copy(tmp_path):
    """Written after the last poll, or while review-api restarted."""
    _write(tmp_path / "abc.partial.json", {"reviews": [1]})
    _write(job_dir(tmp_path, "abc") / "abc.partial.json", {"reviews": [1, 2]})
    prepare_job_dir(tmp_path, "abc")
    for path in (tmp_path, job_dir(tmp_path, "abc")):
        assert json.loads((path / "abc.partial.json").read_text()) == {
            "reviews": [1, 2]}


def test_sync_copies_what_the_worker_wrote(tmp_path):
    folder = job_dir(tmp_path, "abc")
    _write(folder / "abc.progress.json", {"updated_at": 5})
    _write(folder / "abc.json", {"reviews": []})
    _write(folder / "abc.md", "# report")
    sync_job_dir(tmp_path, "abc")
    assert json.loads((tmp_path / "abc.progress.json").read_text()) == {
        "updated_at": 5}
    assert (tmp_path / "abc.json").is_file()
    assert (tmp_path / "abc.md").read_text() == "# report"


def test_sync_follows_the_workers_removals_but_keeps_an_old_report(tmp_path):
    _write(tmp_path / "abc.json", {"previous": "run"})
    _write(tmp_path / "abc.partial.json", {})
    _write(tmp_path / "abc.progress.json", {})
    job_dir(tmp_path, "abc").mkdir(parents=True)
    sync_job_dir(tmp_path, "abc")
    assert not (tmp_path / "abc.partial.json").exists()
    assert not (tmp_path / "abc.progress.json").exists()
    assert json.loads((tmp_path / "abc.json").read_text()) == {
        "previous": "run"}


def test_sync_never_follows_a_link_the_worker_planted(tmp_path):
    """A compromised worker must not make review-api copy ITS OWN files
    (its environment, another report) into a report it then serves."""
    secret = tmp_path / "review-api-secret.txt"
    secret.write_text("REVIEW-API-SECRET", encoding="utf-8")
    folder = job_dir(tmp_path, "abc")
    folder.mkdir(parents=True)
    try:
        os.symlink(secret, folder / "abc.md")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symbolic links here: {exc}")
    sync_job_dir(tmp_path, "abc")
    assert not (tmp_path / "abc.md").exists()


def test_sync_refuses_an_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr(k8s_jobs, "MAX_SYNC_BYTES", 10)
    _write(job_dir(tmp_path, "abc") / "abc.json", "x" * 11)
    sync_job_dir(tmp_path, "abc")
    assert not (tmp_path / "abc.json").exists()


def test_sync_skips_a_file_that_has_not_changed(tmp_path):
    _write(job_dir(tmp_path, "abc") / "abc.json", {"v": 1})
    seen = {}
    sync_job_dir(tmp_path, "abc", seen)
    _write(tmp_path / "abc.json", {"touched": "by review-api"})
    sync_job_dir(tmp_path, "abc", seen)            # unchanged: not recopied
    assert json.loads((tmp_path / "abc.json").read_text()) == {
        "touched": "by review-api"}


# ---- the store: folders follow the review's lifecycle ----

def _cfg(tmp_path):
    return SimpleNamespace(
        output_dir=str(tmp_path),
        provider=lambda name: SimpleNamespace(
            base_url="http://lmstudio:1234/v1"))


def _cluster(monkeypatch, statuses, on_read=None):
    reads = iter(statuses)
    created = []

    class Batch:
        def read_namespaced_job_status(self, name, namespace):
            if on_read:
                on_read()
            return SimpleNamespace(status=next(reads))

        def create_namespaced_job(self, namespace, body):
            created.append(body)

        def delete_namespaced_job(self, name, namespace, propagation_policy):
            pass

    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: SimpleNamespace(
        BatchV1Api=Batch, CoreV1Api=lambda: None))
    monkeypatch.setattr(k8s_jobs, "POLL_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(k8s_jobs.threading, "Thread",
                        lambda target, args, **kw: SimpleNamespace(
                            start=lambda: target(*args)))
    return created


def _create(store, review_id="abc"):
    return store.create(review_id=review_id, repo_url="https://github.com/o/r",
                        mode="brief", provider="lmstudio", model="m",
                        system_prompt="p", prompt_info={"system_prompt": "p"})


_RUNNING = SimpleNamespace(succeeded=None, failed=None)
_DONE = SimpleNamespace(succeeded=1, failed=None)


def test_a_finished_review_has_its_report_copied_out_and_its_folder_removed(
        monkeypatch, tmp_path):
    def worker_finishes():
        _write(job_dir(tmp_path, "abc") / "abc.json", {"reviews": []})

    _cluster(monkeypatch, [_RUNNING, _DONE], on_read=worker_finishes)
    job = _create(KubernetesJobStore(_cfg(tmp_path)))
    assert job.status == "completed"
    assert (tmp_path / "abc.json").is_file()
    assert not job_dir(tmp_path, "abc").exists()


def test_a_report_written_only_in_the_folder_counts(monkeypatch, tmp_path):
    """The flat report does not exist until a sync copies it: succeeded
    must sync before it checks, or every review would read as failed."""
    calls = {"n": 0}

    def worker_writes_on_the_last_poll():
        calls["n"] += 1
        if calls["n"] == 2:
            _write(job_dir(tmp_path, "abc") / "abc.json", {"reviews": []})

    _cluster(monkeypatch, [_RUNNING, _DONE],
             on_read=worker_writes_on_the_last_poll)
    job = _create(KubernetesJobStore(_cfg(tmp_path)))
    assert job.status == "completed"


def test_forgetting_a_review_removes_its_folder(tmp_path):
    store = KubernetesJobStore(_cfg(tmp_path))
    prepare_job_dir(tmp_path, "gone")
    assert store.forget("gone") is True
    assert not job_dir(tmp_path, "gone").exists()


def test_the_sweeper_copies_out_an_orphan_and_later_removes_it(monkeypatch,
                                                               tmp_path):
    """review-api restarted while the Job ran: no poller knows it."""
    store = KubernetesJobStore(_cfg(tmp_path))
    _write(job_dir(tmp_path, "orphan") / "orphan.json", {"done": True})
    store.sweep()
    assert (tmp_path / "orphan.json").is_file()
    assert job_dir(tmp_path, "orphan").is_dir()          # still fresh
    monkeypatch.setattr(k8s_jobs, "_wall_clock",
                        lambda: 10 ** 10)                  # long after
    store.sweep()
    assert not job_dir(tmp_path, "orphan").exists()
    assert (tmp_path / "orphan.json").is_file()


def test_the_sweeper_leaves_a_polled_review_alone(monkeypatch, tmp_path):
    store = KubernetesJobStore(_cfg(tmp_path))
    store._launch_attempt = lambda job, prompt, token: None
    job = _create(store, "live")
    job.status = "reviewing"
    _write(job_dir(tmp_path, "live") / "live.json", {})
    store.sweep()
    assert not (tmp_path / "live.json").exists()
