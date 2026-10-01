"""code-review-mcp builds and pushes on its own, from this folder."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]


def test_build_scripts_target_this_image_and_this_folder_only():
    for script in ("build.sh", "build.ps1"):
        text = (HERE / script).read_text(encoding="utf-8")
        assert "code-review-mcp" in text
        assert "--build-context" not in text     # needs nothing from outside


def test_build_script_refuses_to_push_without_a_registry():
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
