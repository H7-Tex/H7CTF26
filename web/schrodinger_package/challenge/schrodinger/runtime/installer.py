"""Install one exact, hash-verified wheel into a per-job target directory."""

import sys
from pathlib import Path

from schrodinger.runtime.executor import ProcessResult, run_bounded


INSTALL_TIMEOUT_SECONDS = 30


def install_wheel(wheel_path: Path, target: Path, workspace: Path) -> ProcessResult:
    command = [
        sys.executable,
        "-I",
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-deps",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--target",
        str(target),
        str(wheel_path),
    ]
    return run_bounded(command, cwd=workspace, timeout=INSTALL_TIMEOUT_SECONDS)
