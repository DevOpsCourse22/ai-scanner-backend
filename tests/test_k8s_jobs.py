"""Tests for the Kubernetes execution mode.

Two parts, neither needing a cluster or the `kubernetes` package:
- `build_job_manifest`, a pure function (dict in, dict out) asserted directly.
- `KubernetesJobStore`'s retry/token logic, with `_launch_attempt` faked so
  no Kubernetes API is touched (see the bottom of this file).

Still exercised only manually against Elad's cluster, once the
scanner-worker image exists: real Job creation, polling and cleanup — see
docs/job-container-contract.md.
"""

from review_api.k8s_jobs import MAX_ATTEMPTS, build_job_manifest


def _manifest(**overrides):
    base = dict(
        k8s_job_name="review-abc-1-f00baa",
        review_id="abc",
        repo_url="https://github.com/owner/repo",
        mode="brief",
        system_prompt="Be a strict security reviewer.",
        lmstudio_base_url="http://100.93.244.39:1234/v1",
    )
    base.update(overrides)
    return build_job_manifest(**base)


def _env(manifest):
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    return {e["name"]: e for e in container["env"]}


def test_required_env_vars_present():
    env = _env(_manifest())
    assert env["REPO_URL"]["value"] == "https://github.com/owner/repo"
    assert env["REVIEW_ID"]["value"] == "abc"
    assert env["MODE"]["value"] == "brief"
    assert env["LMSTUDIO_BASE_URL"]["value"] == "http://100.93.244.39:1234/v1"
    assert env["SYSTEM_PROMPT"]["value"] == "Be a strict security reviewer."


def test_branch_omitted_when_not_given():
    env = _env(_manifest())
    assert "BRANCH" not in env


def test_branch_included_when_given():
    env = _env(_manifest(branch="develop"))
    assert env["BRANCH"]["value"] == "develop"


def test_github_token_uses_secret_ref_never_a_literal():
    manifest = _manifest(secret_name="review-token-abc-1")
    env = _env(manifest)
    assert "GITHUB_TOKEN" in env
    ref = env["GITHUB_TOKEN"]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": "review-token-abc-1", "key": "token"}
    # The literal value must never appear anywhere in the manifest.
    import json
    assert "ghp_" not in json.dumps(manifest)


def test_no_secret_ref_when_no_token_supplied():
    env = _env(_manifest())
    assert "GITHUB_TOKEN" not in env


def test_backoff_limit_zero_k8s_never_retries_a_job_itself():
    manifest = _manifest()
    assert manifest["spec"]["backoffLimit"] == 0
    assert manifest["spec"]["template"]["spec"]["restartPolicy"] == "Never"


def test_security_posture_matches_the_scanner_dockerfile():
    pod_spec = _manifest()["spec"]["template"]["spec"]
    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["securityContext"]["runAsNonRoot"] is True
    container = pod_spec["containers"][0]
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_only_reports_volume_uses_the_pvc():
    volumes = _manifest()["spec"]["template"]["spec"]["volumes"]
    by_name = {v["name"]: v for v in volumes}
    assert "persistentVolumeClaim" in by_name["reports"]
    # The clone workspace must be ephemeral, never the PVC (2026-09-19
    # decision: the PVC holds reports and checkpoints only).
    assert "emptyDir" in by_name["workspace"]
    assert "persistentVolumeClaim" not in by_name["workspace"]


def test_review_id_is_the_only_identifying_label():
    labels = _manifest()["metadata"]["labels"]
    assert labels["ai-scan.io/review-id"] == "abc"
    assert "https://github.com/owner/repo" not in str(labels)


def test_max_attempts_constant_matches_the_agreed_cap():
    # Guards against silently drifting away from the number Elad and Sahar
    # agreed on (2026-09-19) without anyone noticing in a diff.
    assert MAX_ATTEMPTS == 5


# ---- retry / token handling (store logic, `_launch_attempt` faked: no cluster)

from types import SimpleNamespace  # noqa: E402

from review_api.k8s_jobs import KubernetesJobStore  # noqa: E402


def _store_with_recorded_launches():
    store = KubernetesJobStore(SimpleNamespace(output_dir="/nonexistent"))
    launches = []
    store._launch_attempt = lambda job, system_prompt, access_token: \
        launches.append(access_token)
    return store, launches


def _create(store, access_token):
    return store.create(
        review_id="abc", repo_url="https://github.com/owner/private",
        mode="brief", provider="lmstudio", model="m", system_prompt="p",
        prompt_info={"system_prompt": "p"}, access_token=access_token)


def test_retry_reuses_the_token_so_private_repos_can_be_recloned():
    store, launches = _store_with_recorded_launches()
    job = _create(store, "ghp_test_token")
    store._on_job_failed(job, system_prompt=None)
    assert launches == ["ghp_test_token", "ghp_test_token"]
    assert job.attempts == 2


def test_retry_without_a_token_stays_tokenless():
    store, launches = _store_with_recorded_launches()
    job = _create(store, "")
    store._on_job_failed(job, system_prompt=None)
    assert launches == ["", ""]


def test_token_is_forgotten_once_the_review_is_terminal():
    store, _ = _store_with_recorded_launches()
    job = _create(store, "ghp_test_token")
    assert store._tokens[job.job_id] == "ghp_test_token"
    store._finish(job, status="failed", error="boom")
    assert job.job_id not in store._tokens


def test_token_forgotten_when_retry_cap_is_reached():
    store, launches = _store_with_recorded_launches()
    job = _create(store, "ghp_test_token")
    for _ in range(MAX_ATTEMPTS + 1):
        store._on_job_failed(job, system_prompt=None)
    assert job.status == "failed"
    assert job.attempts == MAX_ATTEMPTS
    assert job.job_id not in store._tokens
    assert len(launches) == MAX_ATTEMPTS  # first attempt + retries up to the cap


def test_no_cluster_is_a_truthful_failure_not_a_stuck_review(monkeypatch):
    """Found running the image outside a cluster: create() raised, the API
    answered a bare 500, and the review stayed `queued` with nothing
    running. It must end `failed`, and say why, and forget the token."""
    from review_api import k8s_jobs

    def no_cluster():
        raise k8s_jobs.KubernetesUnavailableError("no kubeconfig")

    monkeypatch.setattr(k8s_jobs, "_k8s_client", no_cluster)
    store = KubernetesJobStore(SimpleNamespace(output_dir="/nonexistent"))
    job = _create(store, "ghp_test_token")
    assert job.status == "failed"
    assert "no kubeconfig" in job.error
    assert job.job_id not in store._tokens
    assert store.active() is None             # the next review is not blocked


# ---- names and labels: the ids the API really accepts (Elad's review) ----

import json  # noqa: E402
import re  # noqa: E402

import pytest  # noqa: E402

from review_api import k8s_jobs  # noqa: E402

_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_LABEL_VALUE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?)?$")

# What `_sanitize_id` in app.py lets through: uppercase, `_`, `.`, up to
# the API's length. "abc" was the only id the tests used to try, which is
# exactly why an uppercase id failing at Job creation went unnoticed.
REAL_IDS = ["abc", "K3S-01", "k3s_01", "Review.2026.09.26", "__x__",
            "a" * 128, "UPPER_" * 20, "9-starts-with-digit", "x.y-"]


@pytest.mark.parametrize("review_id", REAL_IDS)
def test_job_name_is_a_valid_dns_label(review_id):
    name = k8s_jobs.job_name_for(review_id, 5)
    assert len(name) <= 63, name
    assert _DNS_LABEL.match(name), name


def test_ids_that_slug_alike_get_different_job_names():
    """K3S-01 and k3s-01 are two reviews; lowercasing alone would give
    their Jobs the same stem."""
    a = k8s_jobs.job_name_for("K3S-01", 1).rsplit("-", 2)[0]
    b = k8s_jobs.job_name_for("k3s-01", 1).rsplit("-", 2)[0]
    assert a != b


@pytest.mark.parametrize("review_id", REAL_IDS)
def test_review_label_is_a_valid_label_value(review_id):
    value = k8s_jobs.review_label_for(review_id)
    assert len(value) <= 63 and _LABEL_VALUE.match(value), value


@pytest.mark.parametrize("review_id", ["a" * 128, "__x__"])
def test_the_full_id_is_always_in_the_annotation(review_id):
    manifest = _manifest(review_id=review_id)
    assert manifest["metadata"]["annotations"]["ai-scan.io/review-id"] \
        == review_id
    label = manifest["metadata"]["labels"]["ai-scan.io/review-id"]
    assert label == manifest["spec"]["template"]["metadata"]["labels"][
        "ai-scan.io/review-id"]


def test_model_is_passed_to_the_job_when_chosen():
    assert _env(_manifest(model="google/gemma-4-26b-a4b-qat"))[
        "LMSTUDIO_MODEL"]["value"] == "google/gemma-4-26b-a4b-qat"
    assert "LMSTUDIO_MODEL" not in _env(_manifest())


# ---- <id>.error.json: how a failed Job says why (contract v2) ----

def _write_error(tmp_path, review_id="abc", **data):
    (tmp_path / f"{review_id}.error.json").write_text(json.dumps(data),
                                                      encoding="utf-8")


def test_error_file_is_read_and_validated(tmp_path):
    assert k8s_jobs.read_error_file(str(tmp_path), "abc") is None
    (tmp_path / "abc.error.json").write_text("{not json", encoding="utf-8")
    assert k8s_jobs.read_error_file(str(tmp_path), "abc") is None
    _write_error(tmp_path, permanent="true", error="x")   # not a bool
    assert k8s_jobs.read_error_file(str(tmp_path), "abc") is None
    _write_error(tmp_path, permanent=True, error="bad branch")
    assert k8s_jobs.read_error_file(str(tmp_path), "abc") == {
        "permanent": True, "error": "bad branch"}


def test_a_permanent_failure_stops_at_once_with_the_workers_reason():
    store, launches = _store_with_recorded_launches()
    job = _create(store, "ghp_test_token")
    store._on_job_failed(job, system_prompt=None, error_report={
        "permanent": True,
        "error": "permanent: IngestError: Remote branch nope not found"})
    assert job.status == "failed"
    assert "Remote branch nope" in job.error
    assert launches == ["ghp_test_token"]        # no retry
    assert job.job_id not in store._tokens


def test_a_retryable_failure_is_retried_and_says_why():
    store, launches = _store_with_recorded_launches()
    job = _create(store, "")
    store._on_job_failed(job, system_prompt=None, error_report={
        "permanent": False, "error": "retryable: LLMUnavailableError: down"})
    assert len(launches) == 2
    assert "LLMUnavailableError" in job.message
    assert "retrying (attempt 2/5)" in job.message


def test_no_error_file_means_retry():
    """OOM kill, node lost: the worker never got to write one."""
    store, launches = _store_with_recorded_launches()
    job = _create(store, "")
    store._on_job_failed(job, system_prompt=None, error_report=None)
    assert len(launches) == 2 and job.status != "failed"


def test_the_last_attempt_keeps_the_workers_reason():
    store, _ = _store_with_recorded_launches()
    job = _create(store, "")
    job.attempts = MAX_ATTEMPTS
    store._on_job_failed(job, system_prompt=None, error_report={
        "permanent": False, "error": "retryable: LLMUnavailableError: down"})
    assert job.status == "failed"
    assert "LLMUnavailableError" in job.error and "5 attempts" in job.error


# ---- the poller, against a fake Kubernetes API ----

def _cfg(tmp_path):
    return SimpleNamespace(
        output_dir=str(tmp_path),
        provider=lambda name: SimpleNamespace(
            base_url="http://lmstudio:1234/v1"))


class _ApiError(Exception):
    def __init__(self, status):
        super().__init__(f"({status})")
        self.status = status


def _fake_cluster(monkeypatch, statuses):
    """`statuses`: what each read_namespaced_job_status call returns (a
    status object) or raises (an exception). Records created Jobs."""
    reads = iter(statuses)
    created, deleted = [], []

    class Batch:
        def read_namespaced_job_status(self, name, namespace):
            item = next(reads)
            if isinstance(item, Exception):
                raise item
            return SimpleNamespace(status=item)

        def create_namespaced_job(self, namespace, body):
            created.append(body)

        def delete_namespaced_job(self, name, namespace, propagation_policy):
            deleted.append(name)

    fake = SimpleNamespace(BatchV1Api=Batch, CoreV1Api=lambda: None)
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: fake)
    monkeypatch.setattr(k8s_jobs, "POLL_INTERVAL_SECONDS", 0)
    # Run polls inline, in the test's thread, instead of on a daemon thread.
    monkeypatch.setattr(k8s_jobs.threading, "Thread",
                        lambda target, args, **kw: SimpleNamespace(
                            start=lambda: target(*args)))
    return created, deleted


_RUNNING = SimpleNamespace(succeeded=None, failed=None)
_FAILED = SimpleNamespace(succeeded=None, failed=1)


def test_a_job_deleted_outside_review_api_ends_the_review(monkeypatch,
                                                          tmp_path):
    """Used to be `except Exception: continue` inside `while True`: a 404
    forever, and the review stuck on `reviewing`."""
    created, _ = _fake_cluster(monkeypatch, [_RUNNING, _ApiError(404)])
    store = KubernetesJobStore(_cfg(tmp_path))
    job = _create(store, "")
    assert job.status == "failed"
    assert "disappeared" in job.error
    assert len(created) == 1                        # not retried


def test_api_errors_give_up_after_the_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(k8s_jobs, "MAX_POLL_ERRORS", 3)
    _fake_cluster(monkeypatch, [_ApiError(500)] * 3)
    store = KubernetesJobStore(_cfg(tmp_path))
    job = _create(store, "")
    assert job.status == "failed" and "Lost contact" in job.error


def test_an_api_hiccup_is_ridden_out(monkeypatch, tmp_path):
    monkeypatch.setattr(k8s_jobs, "MAX_POLL_ERRORS", 3)
    (tmp_path / "abc.json").write_text("{}", encoding="utf-8")
    _fake_cluster(monkeypatch, [_ApiError(500), _ApiError(503), _RUNNING,
                                _ApiError(500), _ApiError(500),
                                SimpleNamespace(succeeded=1, failed=None)])
    store = KubernetesJobStore(_cfg(tmp_path))
    job = _create(store, "")
    assert job.status == "completed"      # errors reset after a good read


def test_a_failed_job_with_a_permanent_error_file_is_not_retried(
        monkeypatch, tmp_path):
    created, _ = _fake_cluster(monkeypatch, [_FAILED])
    store = KubernetesJobStore(_cfg(tmp_path))
    # The worker writes its error while the Job runs: simulate that by
    # writing it just before the poller reads the failed status.
    original_read = k8s_jobs.read_error_file

    def read_after_worker_wrote(output_dir, review_id):
        _write_error(tmp_path, permanent=True, error="permanent: bad branch")
        return original_read(output_dir, review_id)

    monkeypatch.setattr(k8s_jobs, "read_error_file", read_after_worker_wrote)
    job = _create(store, "")
    assert job.status == "failed" and job.error == "permanent: bad branch"
    assert len(created) == 1


def test_a_stale_error_file_is_removed_before_each_attempt(monkeypatch,
                                                           tmp_path):
    """Attempt 1 wrote a permanent error; attempt 2 must not be judged by
    it if it dies without writing its own."""
    _write_error(tmp_path, permanent=True, error="from an earlier attempt")
    (tmp_path / "abc.json").write_text("{}", encoding="utf-8")
    _fake_cluster(monkeypatch, [SimpleNamespace(succeeded=1, failed=None)])
    store = KubernetesJobStore(_cfg(tmp_path))
    _create(store, "")
    assert not (tmp_path / "abc.error.json").exists()


def test_created_jobs_carry_a_valid_name_for_an_uppercase_id(monkeypatch,
                                                            tmp_path):
    created, _ = _fake_cluster(monkeypatch, [_RUNNING, _ApiError(404)])
    store = KubernetesJobStore(_cfg(tmp_path))
    store.create(review_id="K3S_Review.01", repo_url="https://github.com/o/r",
                 mode="brief", provider="lmstudio", model="m",
                 system_prompt="p", prompt_info={})
    name = created[0]["metadata"]["name"]
    assert _DNS_LABEL.match(name) and len(name) <= 63
    env = {e["name"]: e.get("value") for e in
           created[0]["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["REVIEW_ID"] == "K3S_Review.01"     # the file key is untouched
    assert env["LMSTUDIO_MODEL"] == "m"


# ---- stuck detection: a stale progress file, not wall-clock time ----

def _clock(monkeypatch, start=10_000.0):
    now = {"t": start}
    monkeypatch.setattr(k8s_jobs, "_wall_clock", lambda: now["t"])
    return now


def _progress(tmp_path, updated_at, review_id="abc"):
    (tmp_path / f"{review_id}.progress.json").write_text(
        json.dumps({"current_file": "", "current_started_at": None,
                    "durations": [], "updated_at": updated_at}), "utf-8")


def test_a_slow_review_that_keeps_progressing_is_never_stuck(monkeypatch,
                                                             tmp_path):
    """Hours of wall-clock time are fine as long as progress.json moves."""
    monkeypatch.setattr(k8s_jobs, "STALE_PROGRESS_SECONDS", 900)
    now = _clock(monkeypatch)
    polls = iter(range(1, 100))

    class Running:
        """Each poll: an hour later, and the worker wrote a minute ago."""
        succeeded, failed = None, None

        def __init__(self):
            now["t"] += 3600 * next(polls)
            _progress(tmp_path, now["t"] - 60)

    (tmp_path / "abc.json").write_text("{}", encoding="utf-8")
    statuses = [Running, Running, Running,
                SimpleNamespace(succeeded=1, failed=None)]
    reads = iter(statuses)
    created, deleted = _fake_cluster(monkeypatch, [])
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: _batch_returning(
        reads, created, deleted))
    job = _create(KubernetesJobStore(_cfg(tmp_path)), "")
    assert job.status == "completed" and deleted == [created[0]["metadata"]
                                                     ["name"]]


def _batch_returning(reads, created, deleted):
    class Batch:
        def read_namespaced_job_status(self, name, namespace):
            item = next(reads)
            return SimpleNamespace(status=item() if isinstance(item, type)
                                   else item)

        def create_namespaced_job(self, namespace, body):
            created.append(body)

        def delete_namespaced_job(self, name, namespace, propagation_policy):
            deleted.append(name)
    return SimpleNamespace(BatchV1Api=Batch, CoreV1Api=lambda: None)


def test_a_stale_progress_file_marks_the_job_stuck_and_retries(monkeypatch,
                                                               tmp_path):
    monkeypatch.setattr(k8s_jobs, "STALE_PROGRESS_SECONDS", 900)
    now = _clock(monkeypatch)
    _progress(tmp_path, now["t"])                  # fresh at the start...

    class Hung:
        succeeded, failed = None, None

        def __init__(self):
            now["t"] += 16 * 60                    # ...then nothing for 16 min

    (tmp_path / "abc.json").write_text("{}", encoding="utf-8")
    reads = iter([Hung, SimpleNamespace(succeeded=1, failed=None)])
    created, deleted = [], []
    _fake_cluster(monkeypatch, [])
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: _batch_returning(
        reads, created, deleted))
    job = _create(KubernetesJobStore(_cfg(tmp_path)), "")
    assert len(created) == 2                       # the stuck one, the retry
    assert deleted[0] == created[0]["metadata"]["name"]
    assert job.attempts == 2 and job.status == "completed"


def test_the_stuck_reason_is_kept_when_attempts_run_out(monkeypatch,
                                                        tmp_path):
    monkeypatch.setattr(k8s_jobs, "STALE_PROGRESS_SECONDS", 900)
    monkeypatch.setattr(k8s_jobs, "MAX_ATTEMPTS", 1)
    now = _clock(monkeypatch)

    class Hung:
        succeeded, failed = None, None

        def __init__(self):
            now["t"] += 20 * 60

    created, deleted = [], []
    _fake_cluster(monkeypatch, [])
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: _batch_returning(
        iter([Hung]), created, deleted))
    job = _create(KubernetesJobStore(_cfg(tmp_path)), "")
    assert job.status == "failed"
    assert "no progress for 20 minutes" in job.error


def test_an_earlier_attempts_progress_file_cannot_make_a_new_one_stuck(
        monkeypatch, tmp_path):
    """The file on the PVC may be hours old (a previous attempt's). The
    clock for THIS attempt starts when it is launched."""
    monkeypatch.setattr(k8s_jobs, "STALE_PROGRESS_SECONDS", 900)
    now = _clock(monkeypatch)
    _progress(tmp_path, now["t"] - 5 * 3600)

    class Starting:
        succeeded, failed = None, None

        def __init__(self):
            now["t"] += 60                         # image pull, clone...

    (tmp_path / "abc.json").write_text("{}", encoding="utf-8")
    created, deleted = [], []
    _fake_cluster(monkeypatch, [])
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: _batch_returning(
        iter([Starting, Starting, SimpleNamespace(succeeded=1, failed=None)]),
        created, deleted))
    job = _create(KubernetesJobStore(_cfg(tmp_path)), "")
    assert job.status == "completed" and len(created) == 1


def test_a_finished_worker_is_not_killed_before_its_job_succeeds(
        monkeypatch, tmp_path):
    """2026-10-09, gw-804074df13ff: a 50-minute deep review finished, the
    worker deleted progress.json, and the next poll still saw the Job
    running (Kubernetes marks it succeeded a few seconds later). With no
    file, idle was counted from the attempt's start - 50 minutes - so the
    finished Job was deleted as stuck and the review rerun from scratch."""
    monkeypatch.setattr(k8s_jobs, "STALE_PROGRESS_SECONDS", 900)
    now = _clock(monkeypatch)
    progress = tmp_path / "abc.progress.json"

    class Reviewing:
        """Ten minutes later each poll, and the worker wrote just now."""
        succeeded, failed = None, None

        def __init__(self):
            now["t"] += 600
            _progress(tmp_path, now["t"] - 5)

    class JustFinished:
        """The worker is done and removed its file; the Job is not yet
        marked succeeded."""
        succeeded, failed = None, None

        def __init__(self):
            now["t"] += 5
            progress.unlink(missing_ok=True)

    (tmp_path / "abc.json").write_text("{}", encoding="utf-8")
    created, deleted = [], []
    _fake_cluster(monkeypatch, [])
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: _batch_returning(
        iter([Reviewing] * 5 + [JustFinished, JustFinished,
                                SimpleNamespace(succeeded=1, failed=None)]),
        created, deleted))
    job = _create(KubernetesJobStore(_cfg(tmp_path)), "")
    assert job.status == "completed"
    assert len(created) == 1 and job.attempts == 1  # no retry, no rerun


def test_the_deadline_is_only_a_high_backstop():
    manifest = _manifest()
    assert manifest["spec"]["activeDeadlineSeconds"] >= 12 * 3600
    assert k8s_jobs.STALE_PROGRESS_SECONDS <= 30 * 60


# ---- pause / resume (contract v3) ----

def test_commit_is_passed_to_the_job_only_when_pinned():
    assert "COMMIT" not in _env(_manifest())
    assert _env(_manifest(commit="b" * 40))["COMMIT"]["value"] == "b" * 40


def test_pause_deletes_the_job_and_stays_paused(monkeypatch, tmp_path):
    """The poller races pause(): it sees the Job gone (404) right after.
    That must not turn a paused review into a failed one."""
    store = KubernetesJobStore(_cfg(tmp_path))
    deleted = []

    class Batch:
        def read_namespaced_job_status(self, name, namespace):
            raise _ApiError(404)

        def create_namespaced_job(self, namespace, body):
            pass

        def delete_namespaced_job(self, name, namespace, propagation_policy):
            deleted.append(name)

    secrets = []

    class Core:
        def create_namespaced_secret(self, namespace, body):
            secrets.append(body["metadata"]["name"])

        def delete_namespaced_secret(self, name, namespace):
            secrets.remove(name)

    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: SimpleNamespace(
        BatchV1Api=Batch, CoreV1Api=Core))
    monkeypatch.setattr(k8s_jobs, "POLL_INTERVAL_SECONDS", 0)
    polls = []
    monkeypatch.setattr(k8s_jobs.threading, "Thread",
                        lambda target, args, **kw: SimpleNamespace(
                            start=lambda: polls.append((target, args))))
    job = _create(store, "ghp_test_token")
    assert job.status == "cloning"
    name = store._k8s_job_names[job.job_id]

    assert store.pause(job) is True
    assert deleted == [name]
    assert job.status == "paused" and job.paused_at
    assert job.job_id not in store._tokens          # a resume brings a new one
    assert store.active() is None                   # the engine is free
    marker = json.loads((tmp_path / "abc.paused.json").read_text("utf-8"))
    assert marker["repo_url"] == "https://github.com/owner/private"
    assert "ghp_" not in json.dumps(marker)

    target, args = polls[0]
    target(*args)                                   # the poller's next round
    assert job.status == "paused" and not job.error
    assert secrets == []                            # token Secret removed
    assert store.pause(job) is False                # idempotent, no 2nd delete
    assert deleted == [name]


def test_progress_json_drives_the_status_in_kubernetes_mode(monkeypatch,
                                                            tmp_path):
    now = _clock(monkeypatch)

    class Running:
        succeeded, failed = None, None

        def __init__(self):
            now["t"] += 5
            (tmp_path / "abc.progress.json").write_text(json.dumps({
                "phase": "reviewing", "done": 4, "total": 10, "reused": 7,
                "commit": "c" * 40, "eta_seconds": 120,
                "updated_at": now["t"]}), "utf-8")

    snapshots = []
    original = KubernetesJobStore._apply_progress

    def spy(self, job, started):
        original(self, job, started)
        snapshots.append((job.status, job.done, job.total, job.reused,
                          job.commit, job.eta_seconds))

    monkeypatch.setattr(KubernetesJobStore, "_apply_progress", spy)
    (tmp_path / "abc.json").write_text("{}", encoding="utf-8")
    created, deleted = [], []
    _fake_cluster(monkeypatch, [])
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: _batch_returning(
        iter([Running, SimpleNamespace(succeeded=1, failed=None)]),
        created, deleted))
    job = _create(KubernetesJobStore(_cfg(tmp_path)), "")
    assert snapshots == [("reviewing", 4, 10, 7, "c" * 40, 120)]
    assert job.status == "completed"
    assert job.public()["commit"] == "c" * 40


def test_an_old_attempts_progress_is_not_shown_as_this_ones(monkeypatch,
                                                            tmp_path):
    now = _clock(monkeypatch)
    (tmp_path / "abc.progress.json").write_text(json.dumps({
        "phase": "reviewing", "done": 9, "total": 10,
        "updated_at": now["t"] - 3600}), "utf-8")

    class Starting:
        succeeded, failed = None, None

    (tmp_path / "abc.json").write_text("{}", encoding="utf-8")
    seen = []
    original = KubernetesJobStore._apply_progress
    monkeypatch.setattr(KubernetesJobStore, "_apply_progress",
                        lambda self, job, started: (
                            original(self, job, started),
                            seen.append((job.status, job.done)))[0])
    created, deleted = [], []
    _fake_cluster(monkeypatch, [])
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: _batch_returning(
        iter([Starting, SimpleNamespace(succeeded=1, failed=None)]),
        created, deleted))
    _create(KubernetesJobStore(_cfg(tmp_path)), "")
    assert seen == [("cloning", None)]


def test_a_resume_pins_the_commit_on_the_new_job(monkeypatch, tmp_path):
    created, _ = _fake_cluster(monkeypatch, [_RUNNING, _ApiError(404)])
    store = KubernetesJobStore(_cfg(tmp_path))
    store.create(review_id="abc", repo_url="https://github.com/o/r",
                 mode="deep", provider="lmstudio", model="m",
                 system_prompt="p", prompt_info={"system_prompt": "p"},
                 commit="d" * 40)
    env = {e["name"]: e.get("value") for e in
           created[0]["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["COMMIT"] == "d" * 40


# ---------------- the AI service key from Settings (contract v4) ----------

def test_llm_key_comes_from_the_secret_never_a_literal():
    env = _env(_manifest(secret_name="s", secret_has_token=False,
                         secret_has_llm_key=True))
    assert "GITHUB_TOKEN" not in env
    ref = env["LLM_API_KEY"]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": "s", "key": "llm_api_key"}
    assert "value" not in env["LLM_API_KEY"]


def test_a_review_with_an_llm_key_gets_a_secret_holding_only_that(
        monkeypatch, tmp_path):
    created, _ = _fake_cluster(monkeypatch, [_RUNNING, _ApiError(404)])
    secrets = []

    class Core:
        def create_namespaced_secret(self, namespace, body):
            secrets.append(body)

        def delete_namespaced_secret(self, name, namespace):
            pass

    batch = k8s_jobs._k8s_client().BatchV1Api
    monkeypatch.setattr(k8s_jobs, "_k8s_client", lambda: SimpleNamespace(
        BatchV1Api=batch, CoreV1Api=Core))
    store = KubernetesJobStore(_cfg(tmp_path))
    store.create(review_id="k1", repo_url="https://github.com/o/r",
                 mode="brief", provider="lmstudio", model="gpt-x",
                 system_prompt="p", prompt_info={"system_prompt": "p"},
                 base_url="https://api.openai.com/v1", llm_preset="openai",
                 llm_api_key="sk-secret-123")
    assert secrets[0]["stringData"] == {"llm_api_key": "sk-secret-123"}
    env = {e["name"]: e for e in
           created[0]["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["LMSTUDIO_BASE_URL"]["value"] == "https://api.openai.com/v1"
    assert "LLM_API_KEY" in env and "GITHUB_TOKEN" not in env
    assert "sk-secret-123" not in json.dumps(created[0])
    job = store.get("k1")
    assert job.public()["ai_service"] == "openai"
    assert "sk-secret-123" not in json.dumps(job.public())
    assert not store._llm_keys                 # ended: the key is forgotten
