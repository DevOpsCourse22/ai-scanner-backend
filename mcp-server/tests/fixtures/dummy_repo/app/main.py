"""Entry point with planted command-execution and eval issues."""

import subprocess


def run_user_command(cmd: str) -> int:
    """Planted: shell command execution with shell=True."""
    return subprocess.call(cmd, shell=True)


def compute(expr: str):
    """Planted: eval of user-supplied input."""
    return eval(expr)


# TODO: replace eval with a proper expression parser (planted marker)
