"""scanner-worker as an image: Dockerfile, build scripts, line endings.

Static checks on the things that fail silently when they drift — an image
that ends up as root, writes outside /workspace, loses a pinned scanner, or
a script checked out with CRLF.

The opt-in test at the bottom runs the BUILT image under the Job's
security posture (read-only root, non-root, tmpfs /workspace). It needs
Docker and a prior build, so it only runs with SCANNER_WORKER_IMAGE_TEST=1.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
DOCKERFILE = (HERE / "Dockerfile").read_text(encoding="utf-8")


def _env_block() -> str:
    return re.search(r"^ENV .+?\n\n", DOCKERFILE, re.M | re.S).group(0)


# ---------------- the image ----------------

def test_ends_as_the_numeric_non_root_user_the_job_asserts():
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.M)
    assert users == ["10001:10001"]
    assert "--uid 10001" in DOCKERFILE and "--gid 10001" in DOCKERFILE


@pytest.mark.parametrize("name", ["mcp-server", "scanner"])
def test_packages_arrive_as_named_build_contexts(name):
    assert f"COPY --from={name} " in DOCKERFILE
    placeholder = re.search(rf"^FROM \S+ AS {re.escape(name)}\n(RUN .+?)\n\n",
                            DOCKERFILE, re.M | re.S)
    assert placeholder, f"the {name} fallback stage must come first"
    assert f"--build-context {name}=../{name}" in placeholder.group(1)
    assert "exit 1" in placeholder.group(1)


def test_nothing_is_copied_from_outside_this_folder_any_other_way():
    for src in re.findall(r"^COPY (?!--from)(?:--\S+ )*(\S+)", DOCKERFILE, re.M):
        assert not src.startswith(".."), src


def test_scanners_are_pinned_from_their_official_images():
    assert "COPY --from=aquasec/trivy:0.74.0 /usr/local/bin/trivy " in DOCKERFILE
    assert ("COPY --from=zricethezav/gitleaks:v8.30.1 /usr/bin/gitleaks "
            in DOCKERFILE)
    # Semgrep is a Python dependency of the scanner package.
    assert "./scanner" in re.search(r"^RUN pip install .+", DOCKERFILE,
                                    re.M).group(0)


def test_everything_that_writes_points_into_workspace():
    """readOnlyRootFilesystem: HOME, temp and caches must all be on the
    emptyDir, and reports on the PVC."""
    env = _env_block()
    assert re.search(r"\bTMPDIR=/workspace\b", env)
    for name in ("HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
                 "TRIVY_CACHE_DIR"):
        assert re.search(rf"\b{name}=/workspace/", env), name
    assert "REVIEW_OUTPUT_DIR=/reports" in env
    assert "PYTHONDONTWRITEBYTECODE=1" in env


def test_safe_directory_is_in_the_system_config_not_home():
    """$HOME is an emptyDir, so a --global setting would not exist at run
    time — and it would have to be written at build time as root anyway."""
    assert "git config --system --add safe.directory '*'" in DOCKERFILE
    assert "git config --global" not in DOCKERFILE


def test_job_shaped_no_port_no_healthcheck_exec_form_entrypoint():
    assert not re.search(r"^(EXPOSE|HEALTHCHECK|CMD)\b", DOCKERFILE, re.M)
    assert re.search(r'^ENTRYPOINT \["python", "/app/entrypoint.py"\]$',
                     DOCKERFILE, re.M)


def test_the_build_context_carries_nothing_but_the_entrypoint():
    ignored = (HERE / ".dockerignore").read_text(encoding="utf-8").split()
    for entry in ("tests/", ".env"):
        assert entry in ignored


# ---------------- build scripts ----------------

@pytest.mark.parametrize("name", ["mcp-server", "scanner"])
def test_build_scripts_pass_the_named_contexts(name):
    assert f"--build-context {name}=../{name}" in \
        (HERE / "build.sh").read_text(encoding="utf-8")
    assert f'"{name}=../{name}"' in \
        (HERE / "build.ps1").read_text(encoding="utf-8")


def test_build_scripts_build_this_image():
    assert "IMAGE=scanner-worker" in (HERE / "build.sh").read_text("utf-8")
    assert '$Image = "scanner-worker"' in (HERE / "build.ps1").read_text("utf-8")


def _posix_bash() -> str | None:
    """A bash that can read this checkout's paths.

    From PowerShell, the first `bash` on PATH is often C:\\Windows\\System32\\
    bash.exe — the WSL launcher, which cannot open a C:/ path and exits 127.
    Git Bash sits next to git.exe (Git\\cmd\\git.exe -> Git\\bin\\bash.exe).
    """
    bash = shutil.which("bash")
    if bash and "system32" in bash.lower():
        git = shutil.which("git")
        candidate = Path(git).resolve().parents[1] / "bin" / "bash.exe" \
            if git else None
        bash = str(candidate) if candidate and candidate.is_file() else None
    return bash


def test_build_script_refuses_to_push_without_a_registry():
    """Checked BEFORE building, so this test never invokes docker."""
    bash = _posix_bash()
    if bash is None:
        pytest.skip("needs Git Bash (or any bash that can read C:/ paths)")
    result = subprocess.run([bash, (HERE / "build.sh").as_posix(), "--push"],
                            capture_output=True, text=True,
                            env={**os.environ, "REGISTRY": ""})
    assert result.returncode == 2
    assert "--push needs --registry" in result.stderr


@pytest.mark.parametrize("name", ["Dockerfile", "build.sh", ".dockerignore"])
def test_files_read_by_linux_have_no_crlf(name):
    assert b"\r" not in (HERE / name).read_bytes()


# ---------------- the built image (opt-in) ----------------

IMAGE = os.getenv("SCANNER_WORKER_IMAGE", "scanner-worker:latest")
needs_image = pytest.mark.skipif(
    os.getenv("SCANNER_WORKER_IMAGE_TEST") != "1" or not shutil.which("docker"),
    reason="set SCANNER_WORKER_IMAGE_TEST=1 after building the image")


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """The Job's security posture, as far as `docker run` can express it."""
    cmd = ["docker", "run", "--rm", "--read-only", "--user", "10001:10001",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--tmpfs", "/workspace:rw,exec,uid=10001,gid=10001,size=1g",
           "--tmpfs", "/tmp:rw,uid=10001,gid=10001",
           "--tmpfs", "/reports:rw,uid=10001,gid=10001"]
    for key, value in (env or {}).items():
        cmd += ["-e", f"{key}={value}"]
    return subprocess.run([*cmd, *args, IMAGE],
                          capture_output=True, text=True, timeout=300)


@needs_image
def test_image_missing_inputs_exit_2_under_a_read_only_root():
    result = _run()
    assert result.returncode == 2, result.stderr
    assert "REPO_URL is required" in result.stderr


@needs_image
@pytest.mark.parametrize("tool", ["trivy --version", "gitleaks version",
                                  "semgrep --version", "git --version"])
def test_image_tools_run_under_a_read_only_root(tool):
    result = subprocess.run(
        ["docker", "run", "--rm", "--read-only", "--user", "10001:10001",
         "--tmpfs", "/workspace:rw,exec,uid=10001,gid=10001",
         "--tmpfs", "/tmp:rw,uid=10001,gid=10001",
         "--entrypoint", "sh", IMAGE, "-c",
         f"mkdir -p $HOME && {tool}"],
        capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr


@needs_image
def test_image_safe_directory_is_set_system_wide():
    result = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "git", IMAGE,
         "config", "--system", "--get-all", "safe.directory"],
        capture_output=True, text=True, timeout=120)
    assert result.stdout.strip() == "*"
