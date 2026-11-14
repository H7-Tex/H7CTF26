"""Bounded subprocess execution for pip and the import smoke test."""

from dataclasses import dataclass
import os
import platform
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time


MAX_OUTPUT_BYTES = 16 * 1024
LIMITS_WRAPPER = Path(__file__).with_name("limits.py")


@dataclass
class ProcessResult:
    returncode: int
    output: str
    timed_out: bool
    output_truncated: bool


def sandbox_capabilities() -> dict[str, bool]:
    machine = platform.machine().lower()
    supported_arch = machine in {"x86_64", "amd64", "x64", "aarch64", "arm64"}
    linux_limits = sys.platform == "linux" and supported_arch and LIMITS_WRAPPER.is_file()
    return {
        "wall_clock_timeout": True,
        "process_group_termination": os.name == "posix",
        "bounded_output": True,
        "child_network_isolation": linux_limits,
        "child_process_group_lockdown": linux_limits,
        "cpu_limit": linux_limits,
        "address_space_limit": linux_limits,
        "file_size_limit": linux_limits,
        "process_count_limit": linux_limits,
        "open_file_limit": linux_limits,
    }


def seccomp_self_test() -> bool:
    """Acceptance probe for the child wrapper; intentionally excluded from health."""
    if not sandbox_capabilities()["child_network_isolation"]:
        return False
    probe = """
import errno, socket
status = dict(line.split(':', 1) for line in open('/proc/self/status'))
assert status['NoNewPrivs'].strip() == '1'
assert status['Seccomp'].strip() == '2'
try:
    socket.socket()
except OSError as exc:
    assert exc.errno == errno.EPERM, exc
else:
    raise SystemExit('socket unexpectedly allowed')
print('NO_NEW_PRIVS=1 SECCOMP=2 SOCKET=EPERM')
"""
    with tempfile.TemporaryDirectory(prefix="schrodinger-seccomp-", dir="/tmp") as directory:
        result = run_bounded([sys.executable, "-I", "-c", probe], cwd=Path(directory), timeout=5)
    return result.returncode == 0 and "NO_NEW_PRIVS=1 SECCOMP=2 SOCKET=EPERM" in result.output


def _child_environment(workspace: Path) -> dict[str, str]:
    home = workspace / "home"
    temporary = workspace / "tmp"
    home.mkdir(exist_ok=True)
    temporary.mkdir(exist_ok=True)
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if os.name == "nt" and os.getenv("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def _stop_process_group(process: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def run_bounded(command: list[str], *, cwd: Path, timeout: float) -> ProcessResult:
    cwd = Path(cwd)
    env = _child_environment(cwd)
    actual_command = list(command)
    if sys.platform == "linux":
        actual_command = [sys.executable, "-I", str(LIMITS_WRAPPER), "--", *actual_command]

    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        actual_command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        close_fds=True,
        start_new_session=os.name == "posix",
        creationflags=creationflags,
    )
    chunks: queue.Queue[bytes | None] = queue.Queue(maxsize=8)

    def read_output() -> None:
        try:
            while block := process.stdout.read(4096):
                chunks.put(block)
        finally:
            try:
                chunks.put_nowait(None)
            except queue.Full:
                pass

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    output = bytearray()
    truncated = False
    timed_out = False
    deadline = time.monotonic() + timeout
    drain_deadline = deadline + 2
    finished = False

    while not finished:
        now = time.monotonic()
        if now >= deadline and not timed_out and process.poll() is None:
            timed_out = True
            _stop_process_group(process)
        if timed_out and now >= drain_deadline:
            process.stdout.close()
            break
        try:
            block = chunks.get(timeout=0.05)
        except queue.Empty:
            if process.poll() is not None and not reader.is_alive():
                break
            continue
        if block is None:
            finished = True
            continue
        available = MAX_OUTPUT_BYTES - len(output)
        output.extend(block[:available])
        truncated = truncated or len(block) > available

    if process.poll() is None:
        _stop_process_group(process)
    try:
        returncode = process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        returncode = process.wait()

    decoded = output.decode("utf-8", errors="replace")
    if truncated:
        decoded += "\n[output truncated]"
    return ProcessResult(returncode, decoded, timed_out, truncated)
