"""review-api as a deployable service: image, build script, compose.

Static checks on the artifacts that fail silently when they drift — the image
ending up as root, the console creeping back in, a healthcheck that needs a
key, a compose change that trades localhost away.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parents[1]
# This repository holds review-api (at its root) plus mcp-server/, scanner/
# and scanner-worker/. docker-compose.yml stayed in the umbrella repository
# (hadsahar/DevSecOps-Final-Project, Code-Review-MCP/), so the compose checks
# below run only when that file is reachable as ../docker-compose.yml, i.e.
# from a monorepo checkout.
COMPOSE = HERE.parent / "docker-compose.yml"
DOCKERFILE = (HERE / "Dockerfile").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def api_service() -> dict:
    if not COMPOSE.is_file():
        pytest.skip("docker-compose.yml lives in the umbrella repository")
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return compose["services"]["api"]


# ---------------- the image ----------------

def test_the_image_carries_no_console():
    assert "frontend" not in DOCKERFILE.lower().replace("no ui", "")
    assert "REVIEW_API_FRONTEND_DIR" not in DOCKERFILE


def test_the_image_ends_as_a_numeric_non_root_user():
    """Numeric so Kubernetes can verify runAsNonRoot without guessing."""
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.M)
    assert users and users[-1] == "10001:10001"
    assert "chown app:app /reports" in DOCKERFILE


def test_the_healthcheck_needs_no_key_and_no_model():
    """/api/v1/health returns 401 once REVIEW_API_KEY is set."""
    check = re.search(r"^HEALTHCHECK.*?\n(?!\s)", DOCKERFILE, re.M | re.S).group(0)
    assert "/healthz" in check and "/api/v1/health" not in check


@pytest.mark.parametrize("name", ["mcp-server", "scanner"])
def test_build_context_is_this_folder_plus_named_contexts(name):
    """The shared engine and the scanner tier each arrive via
    --build-context <name>=./<name>, and forgetting either stops the build
    with a message, not a failed pull of an image by that name."""
    assert f"COPY --from={name}" in DOCKERFILE
    # The whole RUN instruction, continuation lines included.
    placeholder = re.search(rf"^FROM \S+ AS {re.escape(name)}\n(RUN .+?)\n\n",
                            DOCKERFILE, re.M | re.S)
    assert placeholder, f"the {name} fallback stage must come first"
    assert f"--build-context {name}=./{name}" in placeholder.group(1)
    assert "exit 1" in placeholder.group(1)


def test_nothing_is_copied_from_outside_this_folder_any_other_way():
    for src in re.findall(r"^COPY (?!--from)(?:--\S+ )*(\S+)", DOCKERFILE, re.M):
        assert not src.startswith(("..", "backend/", "mcp-server/",
                                   "scanner/")), src


def test_the_deterministic_scanners_are_in_the_image():
    """review-api runs the deterministic tier in-process when execution mode
    is `local`, and the scanner hook degrades to "not installed" rather than
    failing. A deployed image missing these still serves requests and still
    produces reports - just AI-only ones, with the missing half showing up
    as an absence nobody is looking for. Pinned upstream images, so the
    versions are fixed and nothing is downloaded at build time."""
    assert "COPY --from=aquasec/trivy:" in DOCKERFILE
    assert "COPY --from=zricethezav/gitleaks:" in DOCKERFILE
    # Semgrep is a Python dependency of the scanner package, not a binary.
    assert "./scanner" in re.search(r"^RUN pip install .+", DOCKERFILE,
                                    re.M).group(0)


def test_the_kubernetes_client_is_in_the_image():
    """kubernetes execution mode imports the client lazily, at the first
    review, so an image without it starts, passes /healthz, and then fails
    every review. Quoted, because [ ] is a glob to the RUN shell."""
    assert '"./backend[kubernetes]"' in re.search(
        r"^RUN pip install .+", DOCKERFILE, re.M).group(0)


def test_local_config_and_secrets_stay_out_of_the_image():
    ignored = (HERE / ".dockerignore").read_text(encoding="utf-8").split()
    for entry in ("tests/", "config/api.yaml", ".env"):
        assert entry in ignored


# ---------------- the build script ----------------

@pytest.mark.parametrize("name", ["mcp-server", "scanner"])
def test_build_script_passes_the_named_contexts(name):
    assert f"--build-context {name}=./{name}" in \
        (HERE / "build.sh").read_text(encoding="utf-8")
    assert f'"{name}=./{name}"' in \
        (HERE / "build.ps1").read_text(encoding="utf-8")


def test_build_script_refuses_to_push_without_a_registry():
    """Checked BEFORE building, so this test never invokes docker."""
    bash = shutil.which("bash")
    # From PowerShell the first bash is often System32\bash.exe, the WSL
    # launcher, which cannot open a C:/ path (exit 127). Use Git Bash,
    # which sits next to git.exe: Git\cmd\git.exe -> Git\bin\bash.exe.
    if bash and "system32" in bash.lower():
        git = shutil.which("git")
        candidate = (Path(git).resolve().parents[1] / "bin" / "bash.exe"
                     if git else None)
        bash = str(candidate) if candidate and candidate.is_file() else None
    if bash is None:
        pytest.skip("needs Git Bash (or any bash that can read C:/ paths)")
    result = subprocess.run([bash, (HERE / "build.sh").as_posix(), "--push"],
                            capture_output=True, text=True,
                            env={**os.environ, "REGISTRY": ""})
    assert result.returncode == 2
    assert "--push needs --registry" in result.stderr


def test_every_service_has_its_own_build_script():
    for folder, image in ((".", "review-api"),
                          ("mcp-server", "code-review-mcp"),
                          ("scanner-worker", "scanner-worker")):
        for script in ("build.sh", "build.ps1"):
            text = (HERE / folder / script).read_text(encoding="utf-8")
            assert image in text, f"{folder}/{script} builds the wrong image"
        assert b"\r" not in (HERE / folder / "build.sh").read_bytes()


# ---------------- compose ----------------

def test_compose_builds_the_api_from_its_own_folder(api_service):
    assert api_service["build"]["context"] == "./backend"
    # Must stay in step with the Dockerfile's named stages: compose is the
    # path most people build by, so a context missing here fails for them
    # and not for whoever ran build.sh.
    assert api_service["build"]["additional_contexts"] == {
        "mcp-server": "./mcp-server", "scanner": "./scanner"}


def test_compose_no_longer_mounts_a_console_into_the_api(api_service):
    assert not any("frontend" in v for v in api_service["volumes"])


def test_compose_healthcheck_uses_healthz(api_service):
    test = " ".join(api_service["healthcheck"]["test"])
    assert "/healthz" in test and "/api/v1/health" not in test


def test_compose_never_gives_up_localhost_to_share_the_api(api_service):
    """Sharing must ADD an address, not move one.

    Publishing only `${REVIEW_API_BIND}:8000:8000` looked correct and worked
    over the tailnet while silently removing the loopback binding, so
    http://localhost:8000 died. The loopback mapping is unconditional; the
    shared one is a second entry defaulting to another loopback alias.
    """
    ports = api_service["ports"]
    assert any(p.startswith("127.0.0.1:") for p in ports)
    shared = [p for p in ports if p.startswith("${REVIEW_API_BIND")]
    assert len(shared) == 1 and ":-127.0.0.2}" in shared[0]
