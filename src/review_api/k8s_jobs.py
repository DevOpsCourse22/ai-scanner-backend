"""Kubernetes-backed review execution ("platform" mode).

`jobs.JobStore` runs a review by calling `run_review(...)` directly, in the
same process, on the same machine, as the API itself — that is the local/
dev control plane, and it stays exactly as it is. This module is the OTHER
implementation of the same job: instead of an in-process function call, a
review becomes a Kubernetes Job, built and polled against the interface
frozen in `docs/job-container-contract.md` (branch `sahar/docs-scale-down`).
Read that document first; this module is its client-side half.

Decisions this module implements (see `docs/SCOPE-DECISIONS.md`,
2026-09-19 entry, agreed with Elad):

* One combined scanner+mcp-server image per review, run as a Job — not two
  networked microservices, because they only ever run in sequence for one
  review.
* Reconciliation is POLLING, not a callback from the Job. `review-api`
  watches Job/Pod status itself. This is what makes automatic retry
  possible: a Job that dies before it could call anyone back is still
  detected, because nothing here is waiting on it to speak first.
* A crashed or failed review is retried by creating a NEW Job for the SAME
  `review_id`, up to `MAX_ATTEMPTS` (5) total. Past that cap the review
  reaches a truthful `failed` terminal state — it must never be left
  silently spinning on `running` forever, and it must never retry quietly
  past the point where a human should be looking at why.
* The PersistentVolumeClaim holds reports and resume checkpoints ONLY.
  The cloned repository lives in a Job-local `emptyDir`, gone with the Pod.
  This module never mounts the PVC as writable for source — only `/reports`.

WHAT THIS MODULE ASSUMES ABOUT THE CLUSTER (not yet true anywhere — this is
written against the contract, not against a running cluster; adjust the
constants below once the real image and PVC exist):

* A container image implementing `docs/job-container-contract.md` is
  available at `SCANNER_WORKER_IMAGE`.
* A PVC named `PVC_NAME` already exists in `namespace`, and `review-api`'s
  own Pod mounts THE SAME PVC at `settings.output_dir` — so once a Job
  finishes, its report is already sitting where `review-api` already looks
  for reports (see `app.py`'s `/api/v1/reports` routes). No separate
  "fetch the result" step is needed; only "has it finished" is.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from . import review_state
from .jobs import ACTIVE, Job, _now, pause_marker_fields  # noqa: F401 - ACTIVE re-exported for app.py

logger = logging.getLogger(__name__)

# A review gets this many total Job attempts (the first run plus retries)
# before it reaches a truthful `failed` state instead of trying again.
# Elad's number: more than this stops being "recover from a transient
# crash" and starts being "something systemic is wrong — go look at it",
# so the cap surfaces that rather than hiding it behind endless retries.
MAX_ATTEMPTS = 5

# How often the poller thread checks a Job's status. Not configurable via
# ApiConfig on purpose — this is an operational tuning knob for whoever
# runs the cluster, not a per-review setting a request body could carry.
POLL_INTERVAL_SECONDS = float(os.getenv("REVIEW_K8S_POLL_SECONDS", "5"))

# A Job attempt is STUCK when its `<review_id>.progress.json` has not moved
# for this long. The worker refreshes that file's `updated_at` on every file
# start and finish and, in between, at least once a minute while anything
# happens (streamed tokens, a phase change) — in every mode. So a review that
# is slow but working never goes stale, and one that hangs (the model stopped
# answering, a scanner wedged) is caught in minutes, not hours. Decided
# 2026-09-27: wall-clock time says nothing about stuck, progress does.
STALE_PROGRESS_SECONDS = int(os.getenv("REVIEW_K8S_STALE_SECONDS",
                                       str(15 * 60)))

# The hard limit Kubernetes enforces on one attempt, whatever its progress.
# Only a backstop now (stuck detection above does the real work): high
# enough that a deep review of a large repository finishes within one
# attempt. Was 30 minutes, which with MAX_ATTEMPTS killed any review
# longer than ~2.5 hours while it was still making progress.
ACTIVE_DEADLINE_SECONDS = int(os.getenv("REVIEW_K8S_JOB_DEADLINE_SECONDS",
                                        str(12 * 60 * 60)))

# Kept out of the Job spec until it exists for real (see module docstring).
# Overridable per-environment without a code change.
SCANNER_WORKER_IMAGE = os.getenv(
    "SCANNER_WORKER_IMAGE", "ai-scan-repos/scanner-worker:latest")
PVC_NAME = os.getenv("REVIEW_REPORTS_PVC", "ai-scan-repos-reports")
DEFAULT_NAMESPACE = os.getenv("REVIEW_K8S_NAMESPACE", "ai-scan-repos")

# Consecutive failed status reads (API server unreachable, throttled) before
# the poller gives up on a Job. At the default 5 s interval: 5 minutes —
# long enough to ride out an API-server restart, short enough that a review
# is never left on `reviewing` indefinitely.
MAX_POLL_ERRORS = int(os.getenv("REVIEW_K8S_MAX_POLL_ERRORS", "60"))

# A label value: at most 63 characters, alphanumerics plus `-_.`, starting
# and ending alphanumeric. A Job NAME is stricter (lowercase DNS label, also
# 63, because the Job controller copies it into the `job-name` label).
_LABEL_VALUE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$")


def _id_hash(review_id: str) -> str:
    """8 hex chars that tell apart ids a lowercase slug would merge
    (K3S-01 / k3s-01 / k3s_01)."""
    return hashlib.sha256(review_id.encode("utf-8")).hexdigest()[:8]


def _slug(review_id: str, limit: int) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", review_id.lower()).strip("-")
    return slug[:limit].rstrip("-")


def job_name_for(review_id: str, attempt: int) -> str:
    """A valid, unique Kubernetes Job name for one attempt of a review.

    review ids come from the API and may carry uppercase, `_` and `.` and be
    up to 128 characters; a Job name must be a lowercase DNS label of at most
    63. So: a readable slug of the id, a hash of the FULL id (so ids that
    slug alike stay distinct), the attempt, and a random suffix (so a review
    re-created after an API restart cannot collide with a leftover Job).
    At most 7 + 31 + 9 + 2 + 5 = 54 characters.
    """
    slug = _slug(review_id, 30)
    base = f"review-{slug}-" if slug else "review-"
    return f"{base}{_id_hash(review_id)}-{attempt}-{uuid.uuid4().hex[:5]}"


def review_label_for(review_id: str) -> str:
    """The `ai-scan.io/review-id` label value: the id itself when it is a
    valid label value, else a slug + hash that is. The full id is always in
    the `ai-scan.io/review-id` ANNOTATION, which has no length limit."""
    if _LABEL_VALUE.match(review_id):
        return review_id
    slug = _slug(review_id, 54)
    return f"{slug}-{_id_hash(review_id)}" if slug else _id_hash(review_id)


def read_error_file(output_dir: str, review_id: str) -> dict[str, Any] | None:
    """The worker's account of why an attempt failed, or None.

    `<review_id>.error.json` on the shared PVC (contract v2): the worker
    writes `{"permanent": bool, "error": str}` on every failure it detects
    itself. None means it could not (OOM kill, node lost) or wrote nothing
    readable — the caller treats that as retryable. Read from the PVC, not
    the Pod status, so review-api needs no `list` on pods (see the
    contract, "error.json").
    """
    path = Path(output_dir) / f"{review_id}.error.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("permanent"),
                                                    bool):
        return None
    return {"permanent": data["permanent"],
            "error": str(data.get("error") or "")[:4000]}


def _wall_clock() -> float:
    """Epoch seconds, as the worker writes them. A seam for tests."""
    return time.time()


def last_progress_at(output_dir: str, review_id: str) -> float | None:
    """`updated_at` from the worker's `<review_id>.progress.json`, or None
    when there is no readable file yet (Pod still starting, image pulling)."""
    path = Path(output_dir) / f"{review_id}.progress.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get("updated_at")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return None
    return float(value) if isinstance(value, (int, float)) else None


class KubernetesUnavailableError(RuntimeError):
    """Raised when the `kubernetes` package or cluster config is missing.

    Kept separate from a bare ImportError so a caller can show the
    operator a fix ("pip install review-api[kubernetes]" or "no
    in-cluster/kubeconfig credentials found") instead of a stack trace.
    """


def _k8s_client():
    """Import and return a configured `kubernetes.client` module.

    Imported lazily, inside a function, so that `local` execution mode
    (the default, and the only mode most contributors ever run) never
    requires the `kubernetes` package to be installed at all.
    """
    try:
        from kubernetes import client, config as kube_config
    except ImportError as exc:
        raise KubernetesUnavailableError(
            "execution_mode=kubernetes requires the optional dependency: "
            "pip install -e './backend[kubernetes]'"
        ) from exc

    try:
        kube_config.load_incluster_config()
    except kube_config.ConfigException:
        try:
            kube_config.load_kube_config()
        except kube_config.ConfigException as exc:
            raise KubernetesUnavailableError(
                "No in-cluster service account and no local kubeconfig "
                "were found. Running outside the cluster needs a working "
                "`kubectl config current-context`."
            ) from exc
    return client


def build_job_manifest(
    *, k8s_job_name: str, review_id: str, repo_url: str, mode: str,
    system_prompt: str, lmstudio_base_url: str, branch: str = "",
    model: str = "", commit: str = "",
    secret_name: str | None = None, secret_has_token: bool = True,
    secret_has_llm_key: bool = False, namespace: str = DEFAULT_NAMESPACE,
    image: str = SCANNER_WORKER_IMAGE, pvc_name: str = PVC_NAME,
) -> dict[str, Any]:
    """Build the Job manifest as a plain dict (the Kubernetes REST shape).

    Deliberately returns a dict rather than a `kubernetes.client.V1Job`
    object: a dict can be constructed and unit-tested (asserted against,
    diffed, snapshotted) without the `kubernetes` package installed at
    all, and `create_namespaced_job` accepts either. This is the one
    function in this module that has no side effects and no cluster
    dependency — the rest of the module's job is to call this and then
    submit what it returns.

    Every field here traces back to a specific requirement:

    * `backoffLimit: 0` — Kubernetes itself must not silently retry inside
      one Job (see `12-kubernetes-architecture.md`); OUR retry (up to
      `MAX_ATTEMPTS`) creates a whole new Job each time, which is an
      observable, countable event instead of an invisible container
      restart loop.
    * `restartPolicy: Never`, no `HEALTHCHECK`-equivalent — a task that
      exits does not have a steady state to be "healthy" in; Kubernetes
      judges this by exit code, not a probe.
    * Non-root, dropped capabilities, no privilege escalation, read-only
      root filesystem, no automounted service-account token — same
      security posture as `scanner/Dockerfile` and everything already
      documented for the scanner tier: this container is handed someone
      else's repository and must be assumed hostile.
    * `emptyDir` for the clone workspace, sized and separate from the PVC
      — the PVC is for reports and checkpoints ONLY (2026-09-19 decision);
      source code must never land on it.
    * `GITHUB_TOKEN` (when present) arrives via `secretKeyRef`, never as a
      literal env value baked into this manifest.
    """
    env = [
        {"name": "REPO_URL", "value": repo_url},
        {"name": "REVIEW_ID", "value": review_id},
        {"name": "MODE", "value": mode},
        {"name": "SYSTEM_PROMPT", "value": system_prompt},
        {"name": "LMSTUDIO_BASE_URL", "value": lmstudio_base_url},
    ]
    if branch:
        env.append({"name": "BRANCH", "value": branch})
    if model:
        # Contract v2: without it the user's model choice is dropped and LM
        # Studio answers with — or loads beside — whatever it has.
        env.append({"name": "LMSTUDIO_MODEL", "value": model})
    if commit:
        # Contract v3: a resume pins the commit its checkpoint was made at,
        # so a branch that moved on while the review was paused cannot make
        # it start over.
        env.append({"name": "COMMIT", "value": commit})
    if secret_name and secret_has_token:
        env.append({
            "name": "GITHUB_TOKEN",
            "valueFrom": {"secretKeyRef": {"name": secret_name,
                                           "key": "token"}},
        })
    if secret_name and secret_has_llm_key:
        # Contract v4: the AI service's API key (Settings, AI model), from
        # the same per-attempt Secret, never as a literal value here.
        env.append({
            "name": "LLM_API_KEY",
            "valueFrom": {"secretKeyRef": {"name": secret_name,
                                           "key": "llm_api_key"}},
        })

    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": k8s_job_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/component": "scanner-worker",
                # Opaque identifiers only, per the platform's labeling rule
                # (no repo names or user-identifying values on a Job).
                # Shortened when the id is not a valid label value.
                "ai-scan.io/review-id": review_label_for(review_id),
            },
            # The exact id, whatever its length or characters.
            "annotations": {"ai-scan.io/review-id": review_id},
        },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": ACTIVE_DEADLINE_SECONDS,
            "ttlSecondsAfterFinished": 600,
            "template": {
                "metadata": {
                    "labels": {
                        "ai-scan.io/review-id": review_label_for(review_id)},
                },
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "scanner-worker",
                        "image": image,
                        "env": env,
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "requests": {"cpu": "500m", "memory": "1Gi"},
                            "limits": {"cpu": "2", "memory": "4Gi"},
                        },
                        "volumeMounts": [
                            {"name": "reports", "mountPath": "/reports"},
                            {"name": "workspace", "mountPath": "/workspace"},
                            {"name": "tmp", "mountPath": "/tmp"},
                        ],
                    }],
                    "volumes": [
                        {"name": "reports",
                         "persistentVolumeClaim": {"claimName": pvc_name}},
                        # Clone workspace: ephemeral, Job-local, sized —
                        # never the PVC. Gone the moment the Pod is.
                        {"name": "workspace",
                         "emptyDir": {"sizeLimit": "2Gi"}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "512Mi"}},
                    ],
                },
            },
        },
    }


class KubernetesJobStore:
    """Same external shape as `jobs.JobStore` (`create`, `get`, `list`,
    `active`, `cancel`), backed by real Kubernetes Jobs instead of an
    in-process thread. Intended as a drop-in for `app.py` when
    `execution_mode=kubernetes` — see `create_store()` at the bottom of
    this module.

    Reuses `jobs.Job` as-is: it is already a plain, serializable record of
    a review's lifecycle with no assumption baked in about HOW the review
    ran, so every existing `/api/v1/reviews/...` route keeps working
    unmodified against a `Job` this class produced.
    """

    def __init__(self, cfg, namespace: str = DEFAULT_NAMESPACE) -> None:
        self.cfg = cfg
        self.namespace = namespace
        self._jobs: dict[str, Job] = {}
        self._by_review_id: dict[str, str] = {}
        self._lock = threading.RLock()
        # One name per review's CURRENT attempt, so the poller and a
        # concurrent cancel() agree on which Kubernetes Job to act on.
        self._k8s_job_names: dict[str, str] = {}
        # The repo access token, kept ONLY in this process's memory and only
        # while its review is active, so an automatic retry can clone a
        # private repo again. Never written to disk or logged; dropped in
        # `_finish`. The per-attempt Kubernetes Secret is still created
        # fresh and deleted after every attempt (see `_cleanup`).
        self._tokens: dict[str, str] = {}
        # The AI service's API key per job, when Settings chose a service
        # that needs one. Same rules as the clone token: memory only, never
        # serialized, forgotten when the job ends.
        self._llm_keys: dict[str, str] = {}

    # ---------------- lookup (identical contract to JobStore) ----------------

    def get(self, key: str) -> Job | None:
        with self._lock:
            job = self._jobs.get(key)
            if job:
                return job
            job_id = self._by_review_id.get(key)
            return self._jobs.get(job_id) if job_id else None

    def list(self, status: str | None = None, limit: int = 50) -> list[Job]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at,
                          reverse=True)
        if status:
            jobs = [j for j in jobs if j.status == status]
        return jobs[:limit]

    def active(self) -> Job | None:
        with self._lock:
            for job in self._jobs.values():
                if job.status in ACTIVE:
                    return job
        return None

    def forget(self, review_id: str) -> bool:
        """Drop a finished or paused review from the registry (it was
        deleted). A running one is refused: stop it first."""
        with self._lock:
            job_id = self._by_review_id.get(review_id)
            job = self._jobs.get(job_id) if job_id else None
            if job is not None and job.status in ACTIVE:
                return False
            self._by_review_id.pop(review_id, None)
            if job_id:
                self._jobs.pop(job_id, None)
                self._tokens.pop(job_id, None)
                self._llm_keys.pop(job_id, None)
            return True

    # ---------------- creation ----------------

    def create(self, *, review_id: str, repo_url: str, mode: str,
              provider: str, model: str, system_prompt: str,
              prompt_info: dict[str, Any], branch: str = "",
              files: list[str] | None = None, findings_file: str = "",
              extensions: list[str] | None = None, access_token: str = "",
              base_url: str = "", commit: str = "", llm_preset: str = "",
              llm_api_key: str = "") -> Job:
        """Register a review and launch its first Kubernetes Job attempt.

        `files`, `findings_file` and `extensions` are accepted for
        signature parity with `JobStore.create` but are not yet part of
        `docs/job-container-contract.md` — the contract only defines
        REPO_URL/REVIEW_ID/MODE/BRANCH/GITHUB_TOKEN/LMSTUDIO_BASE_URL/
        SYSTEM_PROMPT today. Extend the contract first if a manifest field
        is needed for them, rather than smuggling an extra env var in here
        without the YAML side agreeing on it.
        """
        with self._lock:
            job = Job(
                job_id=uuid.uuid4().hex[:12], review_id=review_id,
                repo_url=repo_url, mode=mode, provider=provider, model=model,
                base_url=base_url, branch=branch, files=files,
                findings_file=findings_file,
                authenticated=bool(access_token), prompt=prompt_info,
                commit_pin=commit, llm_preset=llm_preset,
            )
            self._jobs[job.job_id] = job
            self._by_review_id[review_id] = job.job_id
            if access_token:
                self._tokens[job.job_id] = access_token
            if llm_api_key:
                self._llm_keys[job.job_id] = llm_api_key
        self._launch_attempt(job, system_prompt, access_token)
        return job

    def cancel(self, job: Job) -> bool:
        """Delete the running Kubernetes Job; the poller observes this as
        a terminal state and does NOT retry a user-requested cancel."""
        with self._lock:
            if job.status not in ACTIVE:
                return False
            job.cancel_requested = True
            job.message = "cancellation requested"
            job.updated_at = _now()
        k8s_job_name = self._k8s_job_names.get(job.job_id)
        if k8s_job_name:
            try:
                k8s = _k8s_client()
                k8s.BatchV1Api().delete_namespaced_job(
                    name=k8s_job_name, namespace=self.namespace,
                    propagation_policy="Background")
            except Exception:  # noqa: BLE001 - best-effort; poller still
                # notices the Job disappeared and finalizes the status.
                logger.warning("could not delete Job %s for cancel",
                               k8s_job_name, exc_info=True)
        return True

    def pause(self, job: Job) -> bool:
        """Stop a running review NOW and keep it resumable, for days.

        Deletes the Kubernetes Job: the worker gets SIGTERM, and its
        checkpoint already holds every unit finished before that (it is
        written atomically after each one), so at most the unit in flight
        is reviewed again on resume. The status is "paused" at once, and
        `<id>.paused.json` records it on the reports volume, so the review
        still reads as paused after review-api restarts.

        The token is forgotten like at any other stop: a resume, maybe days
        later, brings the user's current one.
        """
        with self._lock:
            if job.status not in ACTIVE or job.pause_requested:
                return False
            job.pause_requested = True
            k8s_job_name = self._k8s_job_names.get(job.job_id)
        if k8s_job_name:
            try:
                _k8s_client().BatchV1Api().delete_namespaced_job(
                    name=k8s_job_name, namespace=self.namespace,
                    propagation_policy="Background")
            except Exception:  # noqa: BLE001 - the TTL/deadline still end it
                logger.warning("could not delete Job %s for pause",
                               k8s_job_name, exc_info=True)
        self._finish(job, status="paused", message="paused - resume any time",
                     paused_at=_now())
        review_state.write_paused(self.cfg.output_dir, job.review_id,
                                  pause_marker_fields(job))
        return True

    # ---------------- execution ----------------

    def _launch_attempt(self, job: Job, system_prompt: str,
                        access_token: str) -> None:
        """Create one Kubernetes Job for the current attempt and start
        polling it. Called for the first attempt and again for each retry
        — `job.review_id` and therefore the report/checkpoint paths on the
        PVC stay identical across attempts; only the Kubernetes Job's own
        name changes, since a Job name cannot be reused."""
        # No cluster credentials, or RBAC refusing the Secret, must end in a
        # truthful `failed` — not an exception out of create() that leaves
        # the review registered and `queued` forever with nothing running.
        try:
            k8s = _k8s_client()
            with self._lock:
                llm_key = self._llm_keys.get(job.job_id, "")
            secret_name = (self._create_token_secret(k8s, job, access_token,
                                                     llm_key)
                           if access_token or llm_key else None)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the API
            self._finish(job, status="failed",
                        error=f"could not reach Kubernetes: {exc}")
            return
        k8s_job_name = job_name_for(job.review_id, job.attempts)
        # A previous attempt's error file must not be read as this one's:
        # if this attempt dies without writing its own, the verdict has to
        # be "unknown, retry", not the old reason. The worker removes it at
        # start too; this covers an attempt that never gets that far.
        try:
            (Path(self.cfg.output_dir)
             / f"{job.review_id}.error.json").unlink(missing_ok=True)
        except OSError:
            logger.warning("could not remove a stale error file for %s",
                           job.review_id, exc_info=True)
        manifest = build_job_manifest(
            k8s_job_name=k8s_job_name, review_id=job.review_id,
            repo_url=job.repo_url, mode=job.mode,
            system_prompt=system_prompt,
            lmstudio_base_url=job.base_url
            or self.cfg.provider(job.provider).base_url,
            branch=job.branch, model=job.model or "",
            commit=job.commit_pin or "",
            secret_name=secret_name,
            secret_has_token=bool(access_token),
            secret_has_llm_key=bool(llm_key),
            namespace=self.namespace,
        )
        try:
            k8s.BatchV1Api().create_namespaced_job(
                namespace=self.namespace, body=manifest)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the API
            self._finish(job, status="failed",
                        error=f"could not create Job: {exc}")
            return

        with self._lock:
            if job.pause_requested:
                # Paused while this attempt was being created: the Job must
                # not run unwatched. Delete it and stop here.
                self._cleanup(k8s_job_name, secret_name)
                return
            self._k8s_job_names[job.job_id] = k8s_job_name
            job.status = "cloning"
            job.message = f"Job {k8s_job_name} created (attempt {job.attempts})"
            job.updated_at = _now()
        threading.Thread(
            target=self._poll, args=(job, k8s_job_name, secret_name),
            daemon=True, name=f"poll-{job.job_id}-{job.attempts}",
        ).start()

    def _create_token_secret(self, k8s, job: Job, access_token: str,
                             llm_key: str = "") -> str:
        """One Secret per attempt, named after the Job, holding nothing
        else. Deleted in `_cleanup` regardless of outcome — never left
        behind for the TTL controller to eventually notice."""
        name = f"review-token-{job.job_id}-{job.attempts}"
        secret = {
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": name, "namespace": self.namespace},
            "type": "Opaque",
            "stringData": {**({"token": access_token} if access_token else {}),
                           **({"llm_api_key": llm_key} if llm_key else {})},
        }
        k8s.CoreV1Api().create_namespaced_secret(
            namespace=self.namespace, body=secret)
        return name

    def _poll(self, job: Job, k8s_job_name: str,
              secret_name: str | None) -> None:
        """Watch one Kubernetes Job attempt to a terminal state.

        Polling, not a callback FROM the Job (2026-09-19 decision): this
        is the piece that makes a crashed Pod recoverable at all. A Job
        that dies before it could POST anything back would be invisible
        to a callback-based design; here, this loop simply stops seeing
        progress and the Job's own terminal status (or the deadline)
        tells the story regardless of how it ended.
        """
        k8s = _k8s_client()
        batch = k8s.BatchV1Api()
        errors = 0
        # Stuck detection counts from whichever is later: this attempt's
        # start, or the worker's last progress write. A progress file left
        # by an EARLIER attempt is older than this start, so it can never
        # make a fresh attempt look stuck.
        attempt_started = _wall_clock()
        while True:
            time.sleep(POLL_INTERVAL_SECONDS)
            with self._lock:
                if job.pause_requested:
                    # pause() deleted the Job and set the status; only the
                    # token Secret is left for this attempt to remove.
                    self._cleanup(None, secret_name)
                    return
                if job.cancel_requested:
                    self._finish(job, status="cancelled",
                                error="Cancelled by request.")
                    self._cleanup(k8s_job_name, secret_name)
                    return
            try:
                status = batch.read_namespaced_job_status(
                    name=k8s_job_name, namespace=self.namespace).status
            except Exception as exc:  # noqa: BLE001 - classified below
                if job.pause_requested:
                    self._cleanup(None, secret_name)
                    return
                if getattr(exc, "status", None) == 404:
                    # Deleted by someone other than cancel() (kubectl, a
                    # namespace cleanup). It will never come back, so
                    # polling on would leave the review on `reviewing`
                    # forever. Not retried: someone removed it on purpose.
                    self._cleanup(None, secret_name)
                    self._finish(job, status="failed", error=(
                        f"Job {k8s_job_name} disappeared from the cluster "
                        "(deleted outside review-api). Start the review "
                        "again to resume from its checkpoint."))
                    return
                errors += 1
                logger.warning("status read failed for Job %s (%d/%d)",
                               k8s_job_name, errors, MAX_POLL_ERRORS,
                               exc_info=True)
                if errors >= MAX_POLL_ERRORS:
                    self._cleanup(k8s_job_name, secret_name)
                    self._finish(job, status="failed", error=(
                        f"Lost contact with the Kubernetes API for Job "
                        f"{k8s_job_name} ({errors} failed status reads): "
                        f"{exc}"))
                    return
                continue
            errors = 0

            if status.succeeded:
                self._cleanup(k8s_job_name, secret_name)
                self._on_job_succeeded(job)
                return
            if status.failed:
                self._cleanup(k8s_job_name, secret_name)
                self._on_job_failed(
                    job, system_prompt=None,
                    error_report=read_error_file(self.cfg.output_dir,
                                                 job.review_id))
                return
            last = max(attempt_started,
                       last_progress_at(self.cfg.output_dir, job.review_id)
                       or 0.0)
            idle = _wall_clock() - last
            if idle > STALE_PROGRESS_SECONDS:
                # Deleting the Job SIGTERMs the worker, which keeps its
                # checkpoint; the retry resumes from there and counts
                # against MAX_ATTEMPTS like any other failed attempt.
                logger.warning("Job %s made no progress for %ds; deleting it "
                               "as stuck", k8s_job_name, idle)
                self._cleanup(k8s_job_name, secret_name)
                self._on_job_failed(job, system_prompt=None, override_error=(
                    f"no progress for {int(idle // 60)} minutes (limit "
                    f"{STALE_PROGRESS_SECONDS // 60}) — treated as stuck"))
                return
            # Still running. The worker's progress.json (contract v3) says
            # which phase it is in and how many units are done; without it
            # (a v2 image, or the Pod still starting) all that is known is
            # that a Pod exists.
            self._apply_progress(job, attempt_started)

    def _apply_progress(self, job: Job, attempt_started: float) -> None:
        """Copy the worker's live progress onto the job record.

        Only a file written during THIS attempt counts: after a pause, the
        previous attempt's file stays on the volume until the new Pod
        replaces it, and its counts belong to a run that is over.
        """
        live = review_state.read_progress(self.cfg.output_dir, job.review_id)
        updated = (live or {}).get("updated_at")
        fresh = isinstance(updated, (int, float)) and updated >= attempt_started
        with self._lock:
            if job.pause_requested or job.status not in ACTIVE:
                return
            job.updated_at = _now()
            if not fresh:
                if job.status == "requested":
                    job.status = "cloning"
                return
            phase = live.get("phase")
            if phase == "starting":
                job.status = "cloning"
            elif phase in ("cloning", "scanning"):
                job.status = phase
            else:
                job.status = "reviewing"
            for key in ("done", "total"):
                if isinstance(live.get(key), int):
                    setattr(job, key, live[key])
            if isinstance(live.get("reused"), int):
                job.reused = live["reused"]
            if live.get("commit"):
                job.commit = str(live["commit"])
            eta = live.get("eta_seconds")
            job.eta_seconds = eta if isinstance(eta, int) else None
            job.message = phase or job.message

    def _on_job_succeeded(self, job: Job) -> None:
        """A Job exiting 0 is necessary but not sufficient (see the
        contract and `12-kubernetes-architecture.md`'s "Job success alone
        does not mean review success"): the report must actually be on
        the shared PVC before this review is truthfully `completed`."""
        report_path = Path(self.cfg.output_dir) / f"{job.review_id}.json"
        if not report_path.is_file():
            self._on_job_failed(
                job, system_prompt=None,
                override_error=(
                    f"Job {job.review_id!r} exited successfully but "
                    f"{report_path.name} is missing from the shared PVC — "
                    "treating as failed rather than reporting success on "
                    "a review with no report."))
            return
        review_state.clear_paused(self.cfg.output_dir, job.review_id)
        self._finish(job, status="completed",
                    report_path=str(report_path),
                    markdown_path=str(report_path.with_suffix(".md")))

    def _on_job_failed(self, job: Job, *, system_prompt: str | None,
                      override_error: str | None = None,
                      error_report: dict[str, Any] | None = None) -> None:
        """A failed attempt either gets retried (new Job, same review_id,
        same checkpoint on the PVC) or — past MAX_ATTEMPTS, or when the
        worker said the failure is permanent — reaches a truthful `failed`
        state. Never left silently on `running`.

        `error_report` is the worker's `<id>.error.json` (see
        `read_error_file`): `permanent: true` (exit 2 — bad URL, no access,
        missing branch) stops at once, because five identical attempts
        would only delay the same answer. `permanent: false`, or no file
        at all (OOM kill, node lost), is retried.
        """
        if error_report and error_report["permanent"]:
            self._finish(job, status="failed", error=(
                error_report["error"] or "The worker reported a permanent "
                "failure without a reason."))
            return
        if error_report and not override_error:
            override_error = error_report["error"] or None
        with self._lock:
            attempts = job.attempts
        if attempts >= MAX_ATTEMPTS:
            self._finish(
                job, status="failed",
                error=(f"{override_error} — " if override_error else "") + (
                    f"Job failed after {attempts} attempts (limit "
                    f"{MAX_ATTEMPTS}). This many failures on the same "
                    "review points at something systemic — check the Pod "
                    "logs rather than retrying further."))
            return
        with self._lock:
            job.attempts += 1
            job.message = (override_error or "attempt failed") + (
                f" — retrying (attempt {job.attempts}/{MAX_ATTEMPTS})")
            job.updated_at = _now()
        # Same review_id => same checkpoint/report path on the PVC, so the
        # combined image resumes from wherever the last attempt stopped
        # (see docs/job-container-contract.md). The token is re-supplied
        # from memory: without it a retry of a private-repo review could
        # never clone and would burn every remaining attempt.
        with self._lock:
            access_token = self._tokens.get(job.job_id, "")
        self._launch_attempt(job, system_prompt or (job.prompt or {}).get(
            "system_prompt", ""), access_token=access_token)

    def _finish(self, job: Job, *, status: str, error: str | None = None,
               **fields: Any) -> None:
        with self._lock:
            if job.pause_requested and status != "paused":
                # A paused review stays paused: the poller, racing pause(),
                # may still see the deleted Job as gone or failed.
                return
            self._tokens.pop(job.job_id, None)  # terminal: forget the token
            self._llm_keys.pop(job.job_id, None)
            job.status = status
            job.finished_at = _now()
            job.updated_at = _now()
            if error:
                job.error = error
                job.message = "review failed" if status == "failed" \
                    else job.message
            for key, value in fields.items():
                setattr(job, key, value)

    def _cleanup(self, k8s_job_name: str | None,
                 secret_name: str | None) -> None:
        """Delete the finished Job's Pods and its token Secret immediately.

        `ttlSecondsAfterFinished` on the Job spec is defense in depth, not
        a substitute — cleanup here is confirmed, not merely scheduled,
        matching the "TTL cleanup does not replace application-confirmed
        cleanup" principle already documented for the scanner tier.
        """
        try:
            k8s = _k8s_client()
        except Exception:  # noqa: BLE001 - TTL controller is the backstop
            logger.warning("no Kubernetes client for cleanup", exc_info=True)
            return
        # None: the Job is already gone (deleted outside review-api); only
        # its token Secret is left to remove.
        if k8s_job_name:
            try:
                k8s.BatchV1Api().delete_namespaced_job(
                    name=k8s_job_name, namespace=self.namespace,
                    propagation_policy="Background")
            except Exception:  # noqa: BLE001 - TTL controller is the backstop
                logger.warning("could not delete finished Job %s",
                               k8s_job_name, exc_info=True)
        if secret_name:
            try:
                k8s.CoreV1Api().delete_namespaced_secret(
                    name=secret_name, namespace=self.namespace)
            except Exception:  # noqa: BLE001
                logger.warning("could not delete Secret %s", secret_name,
                              exc_info=True)


def create_store(cfg):
    """Return the JobStore implementation selected by REVIEW_API_EXECUTION_MODE.

    Not threaded through `ApiConfig`/`config.py` deliberately: which store
    implementation runs is a deployment-time choice about WHERE reviews
    execute, not a review-configuration value a request or a committed
    config file should carry — it belongs with the other host-specific
    environment variables (`REVIEW_API_HOST`, `REVIEW_API_PORT`), read
    directly, not validated as an unknown-key error the way a typo in
    `config/api.yaml` should be.
    """
    from .jobs import JobStore  # local import avoids a cycle with app.py

    mode = os.getenv("REVIEW_API_EXECUTION_MODE", "local").strip().lower()
    if mode == "kubernetes":
        return KubernetesJobStore(cfg, namespace=DEFAULT_NAMESPACE)
    if mode != "local":
        raise ValueError(
            f"REVIEW_API_EXECUTION_MODE must be 'local' or 'kubernetes', "
            f"got {mode!r}.")
    return JobStore(cfg)
