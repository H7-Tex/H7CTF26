import base64
import hashlib
from pathlib import Path
import re
import sys
import tempfile
import threading
import time

from fastapi import FastAPI, HTTPException

from schrodinger.models import InternalRuntimeRequest, RuntimeResult
from schrodinger.runtime.executor import run_bounded, sandbox_capabilities
from schrodinger.runtime.installer import install_wheel
from schrodinger.runtime.parser import resolve_module


SMOKE_TIMEOUT_SECONDS = 8
MAX_JOB_OUTPUT_BYTES = 32 * 1024
# Trust boundary: runtime container == attacker-controlled after package import.
SMOKE_TEST = """
import importlib
import os
import sys

site_directory, module_name = sys.argv[1:]
sys.path.insert(0, site_directory)
if any(key in os.environ for key in ("FLAG", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PIP_INDEX_URL")):
    raise RuntimeError("unexpected environment variable")
print(f"SMOKE_PID:{os.getpid()}", flush=True)
importlib.import_module(module_name)
print(f"Imported {module_name}")
"""


def _bounded_lines(*sections: str) -> list[str]:
    combined = "\n".join(part for part in sections if part)
    combined = re.sub(r"H7CTF\{[^}\r\n]{0,256}\}", "H7CTF{redacted}", combined)
    encoded = combined.encode("utf-8", errors="replace")[:MAX_JOB_OUTPUT_BYTES]
    return encoded.decode("utf-8", errors="ignore").splitlines()[:200]


def create_app(workspace_dir: Path = Path("/tmp")) -> FastAPI:
    app = FastAPI(title="Schrödinger Package Runtime")
    app.state.workspace_dir = Path(workspace_dir)
    app.state.job_lock = threading.Lock()

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "runtime", "sandbox": sandbox_capabilities()}

    @app.post("/jobs", response_model=RuntimeResult, status_code=201)
    def create_job(request: InternalRuntimeRequest):
        if sys.platform == "linux" and not all(sandbox_capabilities().values()):
            raise HTTPException(status_code=503, detail="runtime process limits are unavailable")
        try:
            content = base64.b64decode(request.content_b64, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="content is not valid base64") from None
        if hashlib.sha256(content).hexdigest() != request.expected_sha256:
            raise HTTPException(status_code=409, detail="package bytes failed SHA-256 verification")

        started = time.monotonic()
        output: list[str] = ["Submitted artifact SHA-256 verified."]
        status = "failed"
        installer_sha256 = ""
        module_path = ""
        archive_occurrences = 0
        selected_sha256 = ""
        installed_sha256 = ""
        import_succeeded = False

        with app.state.job_lock:
            try:
                with tempfile.TemporaryDirectory(
                    prefix="schrodinger-runtime-", dir=app.state.workspace_dir
                ) as temporary_directory:
                    workspace = Path(temporary_directory)
                    wheel_path = workspace / Path(request.filename).name
                    wheel_path.write_bytes(content)
                    installer_sha256 = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
                    if installer_sha256 != request.expected_sha256:
                        raise HTTPException(status_code=409, detail="installer input failed SHA-256 verification")

                    resolution = resolve_module(content, request.package_name)
                    module_path = resolution.path
                    archive_occurrences = resolution.occurrences
                    selected_sha256 = resolution.sha256
                    output.append(f"Installed module path: {resolution.path}")
                    target = workspace / "site"
                    install = install_wheel(wheel_path, target, workspace)
                    if install.timed_out:
                        output.append("Wheel installation timed out.")
                    elif install.returncode != 0:
                        output.extend(("Wheel installation failed.", install.output))
                    else:
                        installed_module = target.joinpath(*resolution.path.split("/"))
                        installed_sha256 = hashlib.sha256(installed_module.read_bytes()).hexdigest()
                        output.append(f"Installed module SHA-256: {installed_sha256}")
                        if installed_sha256 != resolution.sha256:
                            output.append("Installed module did not match Runtime's selected archive entry.")
                        else:
                            smoke = run_bounded(
                                [
                                    sys.executable,
                                    "-I",
                                    "-S",
                                    "-c",
                                    SMOKE_TEST,
                                    str(target),
                                    resolution.module_name,
                                ],
                                cwd=workspace,
                                timeout=SMOKE_TIMEOUT_SECONDS,
                            )
                            if smoke.timed_out:
                                output.append("Package import timed out.")
                            elif smoke.returncode != 0:
                                output.extend(("Package import failed.", smoke.output))
                            else:
                                output.extend((install.output, smoke.output))
                                status = "completed"
                                import_succeeded = True
            except HTTPException:
                raise
            except (OSError, RuntimeError, ValueError) as exc:
                output.extend(("Runtime session could not be completed.", str(exc)[:512]))

        duration_ms = round((time.monotonic() - started) * 1000)
        return RuntimeResult(
            artifact_id=request.artifact_id,
            inspection_id=request.inspection_id,
            sha256=request.expected_sha256,
            installer_sha256=installer_sha256,
            module_path=module_path,
            archive_occurrences=archive_occurrences,
            selected_sha256=selected_sha256,
            installed_sha256=installed_sha256,
            import_succeeded=import_succeeded,
            status=status,
            duration_ms=duration_ms,
            output=_bounded_lines(*output),
        )

    return app
app = create_app()
