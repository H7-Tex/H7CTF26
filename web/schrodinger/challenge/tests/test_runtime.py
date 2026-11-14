import base64
import ctypes
import csv
import hashlib
import json
from io import BytesIO, StringIO
import os
import platform as platform_module
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import warnings
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi.testclient import TestClient
import httpx
import pytest

from schrodinger.config import Settings
from schrodinger.inspector.app import create_app as create_inspector_app
from schrodinger.models import RuntimeJob
from schrodinger.portal.app import create_app as create_portal_app
from schrodinger.runtime.app import create_app as create_runtime_app
from schrodinger.runtime.executor import MAX_OUTPUT_BYTES, run_bounded, seccomp_self_test
from schrodinger.store import ArtifactStore


def wheel_bytes(name="astra-runtime-smoke", module_source='__version__ = "1.0.0"\n'):
    distribution = name.replace("_", "-").lower()
    module = distribution.replace("-", "_")
    dist_info = f"{module}-1.0.0.dist-info"
    members = {
        f"{module}/__init__.py": module_source.encode(),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.3\nName: {distribution}\nVersion: 1.0.0\n"
            "Summary: Runtime integration fixture.\nLicense-Expression: MIT\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
    }
    record_path = f"{dist_info}/RECORD"
    rows = [
        (
            path,
            "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode(),
            str(len(content)),
        )
        for path, content in members.items()
    ]
    rows.append((record_path, "", ""))
    record = StringIO()
    csv.writer(record, lineterminator="\n").writerows(rows)
    members[record_path] = record.getvalue().encode()
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path, content in members.items():
            archive.writestr(path, content)
    return f"{module}-1.0.0-py3-none-any.whl", output.getvalue()


def duplicate_module_wheel(name, alternate_source):
    filename, original = wheel_bytes(name)
    module = filename.split("-", 1)[0]
    path = f"{module}/__init__.py"
    output = BytesIO()
    with ZipFile(BytesIO(original)) as source, ZipFile(output, "w", ZIP_DEFLATED) as target:
        for entry in source.infolist():
            target.writestr(entry, source.read(entry))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            target.writestr(path, alternate_source.encode())
    return filename, output.getvalue(), hashlib.sha256(b'__version__ = "1.0.0"\n').hexdigest()


class _ServiceTransport(httpx.AsyncBaseTransport):
    def __init__(self, apps):
        self.transports = {name: httpx.ASGITransport(app=app) for name, app in apps.items()}
        self.runtime_results = []

    async def handle_async_request(self, request):
        response = await self.transports[request.url.host].handle_async_request(request)
        if request.url.host == "runtime" and request.url.path == "/jobs":
            body = await response.aread()
            self.runtime_results.append(json.loads(body))
            return httpx.Response(
                response.status_code, headers=response.headers, content=body, request=request
            )
        return response

    async def aclose(self):
        for transport in self.transports.values():
            await transport.aclose()


def platform(tmp_path, monkeypatch, workspace=None):
    settings = Settings(tmp_path, "http://inspector:8081", "http://runtime:8082")
    portal = create_portal_app(settings=settings)
    inspector = create_inspector_app(tmp_path)
    runtime = create_runtime_app(tmp_path, workspace or tmp_path)
    original_client = httpx.AsyncClient
    transport = _ServiceTransport({"inspector": inspector, "runtime": runtime})

    class InternalClient(original_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("schrodinger.portal.api.httpx.AsyncClient", InternalClient)
    portal.state.runtime_results = transport.runtime_results
    return portal, inspector, runtime


def upload(client, name="astra-runtime-smoke", module_source='__version__ = "1.0.0"\n'):
    filename, content = wheel_bytes(name, module_source)
    response = client.post("/api/v1/packages", files={"file": (filename, content)})
    assert response.status_code == 201, response.text
    return response.json(), content


def test_assured_wheel_installs_smokes_and_persists_same_digest(tmp_path, monkeypatch):
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    portal_app, _, runtime_app = platform(tmp_path, monkeypatch, jobs_dir)
    real_installer = __import__("schrodinger.runtime.app", fromlist=["install_wheel"]).install_wheel
    installer_digests = []

    def inspect_installer_input(path, target, workspace):
        installer_digests.append(hashlib.sha256(path.read_bytes()).hexdigest())
        return real_installer(path, target, workspace)

    monkeypatch.setattr("schrodinger.runtime.app.install_wheel", inspect_installer_input)
    monkeypatch.setenv("FLAG", "H7CTF{must_not_reach_child}")
    monkeypatch.setenv("HTTPS_PROXY", "http://secret.invalid")
    client = TestClient(portal_app)
    uploaded, content = upload(client)
    artifact_id = uploaded["artifact_id"]
    inspection = client.post(f"/api/v1/packages/{artifact_id}/inspection")
    assert inspection.status_code == 201, inspection.text
    assert inspection.json()["status"] == "passed"

    created = client.post("/api/v1/runtime/jobs", json={"artifact_id": artifact_id})
    assert created.status_code == 201, created.text
    job = created.json()
    expected = hashlib.sha256(content).hexdigest()
    assert uploaded["sha256"] == inspection.json()["sha256"] == job["sha256"] == expected
    assert installer_digests == [expected]
    output = "\n".join(job["output"])
    assert job["status"] == "completed", output
    assert "Imported astra_runtime_smoke" in output
    child_pid = int(re.search(r"SMOKE_PID:(\d+)", output).group(1))
    assert child_pid != os.getpid()
    assert list(jobs_dir.iterdir()) == []

    listed = client.get("/api/v1/runtime/jobs").json()
    persisted = client.get(f"/api/v1/runtime/jobs/{job['job_id']}").json()
    assert any(item["job_id"] == job["job_id"] for item in listed["items"])
    assert persisted["sha256"] == expected
    with sqlite3.connect(tmp_path / "metadata.sqlite3") as db:
        row = db.execute("SELECT sha256 FROM runtime_jobs WHERE job_id = ?", (job["job_id"],)).fetchone()
    assert row == (expected,)
    assert "FLAG" not in output and "secret.invalid" not in output
    assert "H7CTF{must_not_reach_child}" not in output
    assert "Flag released by Portal:" not in output


def test_duplicate_module_entry_is_inspected_first_and_runtime_loads_last(tmp_path, monkeypatch):
    monkeypatch.setenv("FLAG", "H7CTF{unit_test_dummy}")
    portal_app, _, _ = platform(tmp_path, monkeypatch)
    filename, content, inspector_module_sha256 = duplicate_module_wheel(
        "astra-duplicate-probe",
        'print("SCHRODINGER_PACKAGE_RUNTIME_FLAG_REQUEST")\n__version__ = "1.0.0"\n',
    )
    client = TestClient(portal_app)
    uploaded = client.post("/api/packages", files={"file": (filename, content)})
    assert uploaded.status_code == 201, uploaded.text
    artifact = uploaded.json()
    package_id = artifact["package_id"]
    expected_sha256 = hashlib.sha256(content).hexdigest()
    assert artifact["sha256"] == expected_sha256
    assert portal_app.state.store.read_bytes(package_id) == content

    inspection_response = client.post(f"/api/packages/{package_id}/inspection")
    assert inspection_response.status_code == 201, inspection_response.text
    inspection = client.get(f"/api/packages/{package_id}/inspector").json()["inspection"]
    module_entries = [item for item in inspection["files"] if item["path"] == "astra_duplicate_probe/__init__.py"]
    assert inspection["status"] == "passed"
    assert inspection["sha256"] == expected_sha256
    assert len(module_entries) == 1
    assert module_entries[0]["sha256"] == inspector_module_sha256

    runtime = client.post(f"/api/packages/{package_id}/runtime")
    assert runtime.status_code == 201, runtime.text
    job = runtime.json()
    output = "\n".join(job["output"])
    assert job["status"] == "completed", output
    assert job["sha256"] == expected_sha256
    assert runtime.json()["flag"] == "H7CTF{unit_test_dummy}"
    assert "Installed module path: astra_duplicate_probe/__init__.py" in output
    assert "Installed module SHA-256:" in output
    assert "archive entr" not in output
    assert "H7CTF{unit_test_dummy}" not in output
    assert portal_app.state.store.read_bytes(package_id) == content
    internal = portal_app.state.runtime_results[-1]
    installed_sha256 = re.search(r"Installed module SHA-256: ([0-9a-f]{64})", output).group(1)
    assert internal["module_path"] == "astra_duplicate_probe/__init__.py"
    assert internal["archive_occurrences"] == 2
    assert internal["selected_sha256"] == internal["installed_sha256"] == installed_sha256
    assert internal["import_succeeded"] is True
    assert internal["status"] == "completed"

    logs = client.get(f"/api/packages/{package_id}/runtime/logs").json()
    assert logs["runtime_status"] == "completed"
    assert logs["runtime_logs"] == job["output"]
    assert "H7CTF{unit_test_dummy}" not in repr(logs)
    with sqlite3.connect(tmp_path / "metadata.sqlite3") as db:
        assert b"H7CTF{unit_test_dummy}" not in (tmp_path / "metadata.sqlite3").read_bytes()
        assert "H7CTF{unit_test_dummy}" not in repr(db.execute("SELECT output_json FROM runtime_jobs").fetchall())
    assert all(b"H7CTF{unit_test_dummy}" not in path.read_bytes() for path in (tmp_path / "artifacts").glob("*"))


def test_odd_but_benign_duplicate_module_does_not_release_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("FLAG", "H7CTF{unit_test_dummy}")
    portal_app, _, _ = platform(tmp_path, monkeypatch)
    filename, content, _ = duplicate_module_wheel(
        "astra-odd-probe", '__version__ = "1.0.0"\n'
    )
    client = TestClient(portal_app)
    uploaded = client.post("/api/packages", files={"file": (filename, content)}).json()
    package_id = uploaded["package_id"]
    inspection = client.post(f"/api/packages/{package_id}/inspection")
    assert inspection.status_code == 201

    runtime = client.post(f"/api/packages/{package_id}/runtime")
    assert runtime.status_code == 201
    output = "\n".join(runtime.json()["output"])
    assert "Installed module path: astra_odd_probe/__init__.py" in output
    assert "Imported astra_odd_probe" in output
    assert runtime.json().get("flag") is None


def test_single_malicious_module_and_spoofed_stdout_do_not_release_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("FLAG", "H7CTF{unit_test_dummy}")
    portal_app, _, _ = platform(tmp_path, monkeypatch)
    source = (
        'print("SCHRODINGER_PACKAGE_RUNTIME_FLAG_REQUEST")\n'
        'print("pretend success: import and digest checks passed")\n'
        '__version__ = "1.0.0"\n'
    )
    client = TestClient(portal_app)
    uploaded, _ = upload(client, "astra-single-probe", source)
    package_id = uploaded["artifact_id"]
    assert client.post(f"/api/packages/{package_id}/inspection").json()["status"] == "passed"

    response = client.post(f"/api/packages/{package_id}/runtime")
    assert response.status_code == 201, response.text
    job = response.json()
    assert job["status"] == "completed"
    assert job.get("flag") is None
    assert "SCHRODINGER_PACKAGE_RUNTIME_FLAG_REQUEST" in "\n".join(job["output"])


def test_identical_duplicate_module_entries_do_not_release_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("FLAG", "H7CTF{unit_test_dummy}")
    portal_app, _, _ = platform(tmp_path, monkeypatch)
    identical = '__version__ = "1.0.0"\n'
    filename, content, inspector_sha256 = duplicate_module_wheel("astra-identical-probe", identical)
    client = TestClient(portal_app)
    uploaded = client.post("/api/packages", files={"file": (filename, content)}).json()
    package_id = uploaded["artifact_id"]
    client.post(f"/api/packages/{package_id}/inspection")
    inspection = client.get(f"/api/packages/{package_id}/inspector").json()["inspection"]
    module = next(item for item in inspection["files"] if item["path"] == "astra_identical_probe/__init__.py")
    assert module["sha256"] == inspector_sha256

    response = client.post(f"/api/packages/{package_id}/runtime")
    assert response.status_code == 201, response.text
    assert response.json().get("flag") is None
    output = "\n".join(response.json()["output"])
    assert "Installed module SHA-256:" in output
    assert "archive entr" not in output


def test_failed_import_never_releases_or_persists_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("FLAG", "H7CTF{unit_test_dummy}")
    portal_app, _, _ = platform(tmp_path, monkeypatch)
    filename, content, _ = duplicate_module_wheel(
        "astra-failing-probe", 'raise RuntimeError("import failed")\n'
    )
    client = TestClient(portal_app)
    uploaded = client.post("/api/packages", files={"file": (filename, content)}).json()
    package_id = uploaded["artifact_id"]
    client.post(f"/api/packages/{package_id}/inspection")
    response = client.post(f"/api/packages/{package_id}/runtime")
    assert response.status_code == 201
    assert response.json()["status"] == "failed"
    assert response.json().get("flag") is None
    assert "H7CTF{unit_test_dummy}" not in repr(response.json())
    assert b"H7CTF{unit_test_dummy}" not in (tmp_path / "metadata.sqlite3").read_bytes()


def test_portal_startup_redacts_legacy_persisted_flag_output(tmp_path):
    store = ArtifactStore(tmp_path)
    filename, content = wheel_bytes("astra-legacy-output")
    artifact = store.create(
        filename, content, package_name="astra-legacy-output", version="1.0.0"
    )
    store.record_runtime_job(
        RuntimeJob(
            job_id="legacy-flag-output",
            artifact_id=artifact.artifact_id,
            package_name=artifact.package_name,
            version=artifact.version,
            sha256=artifact.sha256,
            status="completed",
            created_at="2026-01-01T00:00:00Z",
            duration_ms=1,
            output=["old output H7CTF{legacy_secret_canary}"],
        )
    )

    portal_app = create_portal_app(tmp_path)
    saved = portal_app.state.store.runtime_jobs("legacy-flag-output")[0]
    assert saved.output == ["old output H7CTF{redacted}"]
    assert b"H7CTF{legacy_secret_canary}" not in (tmp_path / "metadata.sqlite3").read_bytes()


def test_runtime_source_disclosure_cannot_release_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("FLAG", "H7CTF{unit_test_dummy}")
    portal_app, _, _ = platform(tmp_path, monkeypatch)
    source = (
        'from pathlib import Path\n'
        'print("Runtime source readable by package code")\n'
        'print("SCHRODINGER_PACKAGE_RUNTIME_FLAG_REQUEST")\n'
        '__version__ = "1.0.0"\n'
    )
    client = TestClient(portal_app)
    uploaded, _ = upload(client, "astra-source-probe", source)
    package_id = uploaded["artifact_id"]
    client.post(f"/api/packages/{package_id}/inspection")
    response = client.post(f"/api/packages/{package_id}/runtime")
    assert response.status_code == 201
    assert response.json().get("flag") is None
    assert "RUNTIME_FLAG_MARKER" not in Path(__file__).parents[1].joinpath(
        "schrodinger/runtime/app.py"
    ).read_text(encoding="utf-8")


def test_unassured_and_rejected_packages_are_not_eligible(tmp_path, monkeypatch):
    portal_app, _, _ = platform(tmp_path, monkeypatch)
    client = TestClient(portal_app)
    artifact, _ = upload(client)
    response = client.post("/api/v1/runtime/jobs", json={"artifact_id": artifact["artifact_id"]})
    assert response.status_code == 409

    broken_zip = BytesIO()
    with ZipFile(broken_zip, "w") as archive:
        archive.writestr("unexpected.txt", "not a wheel layout")
    rejected = client.post(
        "/api/v1/packages",
        files={"file": ("astra_rejected-1.0.0-py3-none-any.whl", broken_zip.getvalue())},
    )
    assert rejected.status_code == 201
    artifact_id = rejected.json()["artifact_id"]
    inspected = client.post(f"/api/v1/packages/{artifact_id}/inspection")
    assert inspected.status_code == 201
    assert inspected.json()["status"] == "rejected"
    assert client.post("/api/v1/runtime/jobs", json={"artifact_id": artifact_id}).status_code == 409


def test_runtime_rehashes_and_checks_expected_digest_independently(tmp_path, monkeypatch):
    portal_app, _, runtime_app = platform(tmp_path, monkeypatch)
    client = TestClient(portal_app)
    artifact, content = upload(client)
    artifact_id = artifact["artifact_id"]
    inspection = client.post(f"/api/v1/packages/{artifact_id}/inspection").json()
    internal = TestClient(runtime_app)
    request = {
        "artifact_id": artifact_id,
        "inspection_id": inspection["inspection_id"],
        "expected_sha256": artifact["sha256"],
    }
    bad_digest = {**request, "expected_sha256": "0" * 64}
    assert internal.post("/jobs", json=bad_digest).status_code == 409

    bad_inspection = {**request, "inspection_id": "player-supplied-unbound-inspection"}
    assert internal.post("/jobs", json=bad_inspection).status_code == 409
    bad_artifact = {**request, "artifact_id": "f" * 32}
    assert internal.post("/jobs", json=bad_artifact).status_code == 404

    with sqlite3.connect(tmp_path / "metadata.sqlite3") as db:
        db.execute(
            "UPDATE inspections SET sha256 = ? WHERE inspection_id = ?",
            ("f" * 64, request["inspection_id"]),
        )
    assert internal.post("/jobs", json=request).status_code == 409
    with sqlite3.connect(tmp_path / "metadata.sqlite3") as db:
        db.execute(
            "UPDATE inspections SET sha256 = ? WHERE inspection_id = ?",
            (artifact["sha256"], request["inspection_id"]),
        )

    blob = portal_app.state.store.blobs / f"{artifact_id}.whl"
    blob.write_bytes(content + b"tampered")
    assert internal.post("/jobs", json=request).status_code == 409
    assert client.post("/api/v1/runtime/jobs", json={"artifact_id": artifact_id}).status_code == 409


def test_public_runtime_request_rejects_execution_overrides(tmp_path):
    client = TestClient(create_portal_app(data_dir=tmp_path))
    artifact_id = client.get("/api/v1/packages").json()["items"][0]["artifact_id"]
    for extra in ({"command": "id"}, {"module": "os"}, {"sha256": "0" * 64}, {"expected_sha256": "0" * 64}):
        response = client.post("/api/v1/runtime/jobs", json={"artifact_id": artifact_id, **extra})
        assert response.status_code == 422


def test_runtime_readonly_store_does_not_initialize_or_write(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(FileNotFoundError):
        ArtifactStore(missing, readonly=True)
    assert not missing.exists()

    writable = ArtifactStore(tmp_path / "data")
    artifact = writable.create("package.whl", b"wheel", package_name="package", version="1.0")
    reader = ArtifactStore(writable.root, readonly=True)
    assert reader.get(artifact.artifact_id) == artifact
    job = RuntimeJob(
        job_id="test-job",
        artifact_id=artifact.artifact_id,
        package_name=artifact.package_name,
        version=artifact.version,
        sha256=artifact.sha256,
        status="completed",
        created_at=artifact.created_at,
        duration_ms=1,
        output=[],
    )
    with pytest.raises(PermissionError):
        reader.record_runtime_job(job)
    with reader._connect() as db, pytest.raises(sqlite3.OperationalError):
        db.execute("UPDATE artifacts SET version = 'changed'")


def test_runtime_timeout_kills_child_and_output_is_bounded(tmp_path):
    workdir = tmp_path / "process"
    workdir.mkdir()
    started = time.monotonic()
    timed_out = run_bounded(
        [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
        cwd=workdir,
        timeout=0.25,
    )
    assert timed_out.timed_out
    assert time.monotonic() - started < 5

    noisy = run_bounded(
        [sys.executable, "-I", "-c", "print('x' * 100000)"],
        cwd=workdir,
        timeout=5,
    )
    assert noisy.returncode == 0
    assert noisy.output_truncated
    assert len(noisy.output.encode()) <= MAX_OUTPUT_BYTES + 32


def test_runtime_child_environment_is_an_allowlist(tmp_path, monkeypatch):
    workdir = tmp_path / "environment"
    workdir.mkdir()
    sensitive = {
        "FLAG": "H7CTF{environment_canary}",
        "AWS_SECRET_ACCESS_KEY": "credential-canary",
        "DATABASE_URL": "sqlite:///secret.db",
        "INSPECTOR_URL": "http://inspector.internal",
        "RUNTIME_URL": "http://runtime.internal",
        "PIP_INDEX_URL": "https://index.invalid",
        "HTTPS_PROXY": "http://proxy.invalid",
    }
    for key, value in sensitive.items():
        monkeypatch.setenv(key, value)

    result = run_bounded(
        [sys.executable, "-I", "-c", "import json,os; print(json.dumps(dict(os.environ)))"],
        cwd=workdir,
        timeout=5,
    )

    assert result.returncode == 0, result.output
    child_env = json.loads(result.output)
    assert not sensitive.keys() & child_env.keys()
    assert set(child_env) == {
        "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "PIP_CONFIG_FILE",
        "PIP_DISABLE_PIP_VERSION_CHECK", "PYTHONNOUSERSITE", "PYTHONUTF8", "LANG", "LC_ALL",
        *( {"SYSTEMROOT"} if os.name == "nt" and os.getenv("SYSTEMROOT") else set() ),
    }


@pytest.mark.skipif(sys.platform != "linux", reason="procfs and seccomp are Linux-specific")
def test_linux_child_procfs_can_read_parent_env_despite_popen_environment(tmp_path):
    """Document the container boundary: a clean child env does not hide its parent."""
    workdir = tmp_path / "procfs"
    workdir.mkdir()
    project = str(Path(__file__).parents[1].resolve())
    child_code = (
        "import os; print('CHILD_HAS_CANARY=' + str('PROCFS_PARENT_CANARY' in os.environ)); "
        "data=open(f'/proc/{os.getppid()}/environ','rb').read(); "
        "print('PROCFS_PARENT_CANARY_VISIBLE' if b'PROCFS_PARENT_CANARY=visible' in data "
        "else 'PROCFS_PARENT_CANARY_HIDDEN')"
    )
    parent_code = """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from schrodinger.runtime.executor import run_bounded
result = run_bounded([sys.executable, '-I', '-c', sys.argv[3]], cwd=Path(sys.argv[2]), timeout=20)
print(result.output)
"""
    parent_env = os.environ.copy()
    parent_env["PROCFS_PARENT_CANARY"] = "visible"
    parent = subprocess.run(
        [sys.executable, "-c", parent_code, project, str(workdir), child_code],
        env=parent_env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert parent.returncode == 0, parent.stderr
    assert "CHILD_HAS_CANARY=False" in parent.stdout
    assert "PROCFS_PARENT_CANARY_VISIBLE" in parent.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp is enforced in the runtime image")
def test_linux_child_cannot_open_sockets_or_signal_runtime_parent(tmp_path):
    workdir = tmp_path / "seccomp"
    workdir.mkdir()
    code = """
import errno, os, socket
try:
    socket.socket()
except OSError as exc:
    assert exc.errno == errno.EPERM, exc
    print('SOCKET_BLOCKED')
else:
    raise SystemExit('socket unexpectedly allowed')
try:
    os.kill(os.getppid(), 0)
except PermissionError:
    print('PARENT_SIGNAL_BLOCKED')
else:
    raise SystemExit('parent signaling unexpectedly allowed')
"""
    result = run_bounded([sys.executable, "-I", "-c", code], cwd=workdir, timeout=5)
    assert result.returncode == 0, result.output
    assert "SOCKET_BLOCKED" in result.output
    assert "PARENT_SIGNAL_BLOCKED" in result.output


@pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp is enforced in the runtime image")
def test_linux_seccomp_blocks_process_inspection_and_control_syscalls(tmp_path):
    workdir = tmp_path / "process-api"
    workdir.mkdir()
    code = r"""
import ctypes, errno, os, platform, socket

libc = ctypes.CDLL(None, use_errno=True)
status = dict(line.split(':', 1) for line in open('/proc/self/status'))
assert status['NoNewPrivs'].strip() == '1' and status['Seccomp'].strip() == '2'
def blocked(number, *args):
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    assert result == -1 and ctypes.get_errno() == errno.EPERM, (number, result, ctypes.get_errno())

machine = platform.machine().lower()
if machine in ('x86_64', 'amd64'):
    calls = {'ptrace': 101, 'process_vm_readv': 310, 'process_vm_writev': 311,
             'pidfd_send_signal': 424, 'pidfd_open': 434, 'pidfd_getfd': 438,
             'kill': 62, 'tkill': 200, 'tgkill': 234, 'rt_sigqueueinfo': 129,
             'rt_tgsigqueueinfo': 297, 'setpgid': 109, 'setsid': 112}
elif machine in ('aarch64', 'arm64'):
    calls = {'ptrace': 117, 'process_vm_readv': 270, 'process_vm_writev': 271,
             'pidfd_send_signal': 424, 'pidfd_open': 434, 'pidfd_getfd': 438,
             'kill': 129, 'tkill': 130, 'tgkill': 131, 'rt_sigqueueinfo': 138,
             'rt_tgsigqueueinfo': 240, 'setpgid': 154, 'setsid': 157}
else:
    raise SystemExit('unsupported test architecture: ' + machine)

parent = os.getppid()
blocked(calls['ptrace'], 16, parent, 0, 0)
class IOVec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
local = ctypes.create_string_buffer(b'x')
local_iov = IOVec(ctypes.cast(local, ctypes.c_void_p), 1)
remote_iov = IOVec(ctypes.c_void_p(1), 1)
blocked(calls['process_vm_readv'], parent, ctypes.byref(local_iov), 1, ctypes.byref(remote_iov), 1, 0)
blocked(calls['process_vm_writev'], parent, ctypes.byref(local_iov), 1, ctypes.byref(remote_iov), 1, 0)
blocked(calls['pidfd_open'], parent, 0)
blocked(calls['pidfd_getfd'], -1, 0, 0)
blocked(calls['pidfd_send_signal'], parent, 0, 0, 0)
blocked(calls['kill'], parent, 0)
blocked(calls['tkill'], parent, 0)
blocked(calls['tgkill'], parent, parent, 0)
blocked(calls['rt_sigqueueinfo'], parent, 0, 0)
blocked(calls['rt_tgsigqueueinfo'], parent, parent, 0, 0)

pid = os.fork()
if pid == 0:
    try:
        os.setsid()
    except OSError as exc:
        if exc.errno != errno.EPERM: os._exit(21)
    else:
        os._exit(22)
    try:
        os.setpgid(0, 0)
    except OSError as exc:
        if exc.errno != errno.EPERM: os._exit(23)
    else:
        os._exit(24)
    os._exit(0)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 0

descendant_code = ("import errno,socket\n" "try:\n socket.socket()\n"
                  "except OSError as e:\n print(e.errno)\n"
                  "else:\n raise SystemExit(2)\n")
descendant = __import__('subprocess').run(
    [os.path.realpath(os.sys.executable), '-I', '-c', descendant_code],
    capture_output=True, text=True, check=False)
assert descendant.returncode == 0 and descendant.stdout.strip() == str(errno.EPERM), descendant
print('PROCESS_APIS_BLOCKED DESCENDANT_FILTER_INHERITED GROUP_CHANGES_BLOCKED')
"""
    result = run_bounded([sys.executable, "-I", "-c", code], cwd=workdir, timeout=20)
    assert result.returncode == 0, result.output
    assert "PROCESS_APIS_BLOCKED DESCENDANT_FILTER_INHERITED GROUP_CHANGES_BLOCKED" in result.output


@pytest.mark.skipif(sys.platform != "linux", reason="Linux x32 syscall ABI is specific to x86_64")
def test_x86_64_x32_socket_syscall_is_rejected(tmp_path):
    if platform_module.machine().lower() not in {"x86_64", "amd64", "x64"}:
        pytest.skip("x32 syscall-number ABI only applies to x86_64")
    workdir = tmp_path / "x32"
    workdir.mkdir()
    code = r"""
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
result = libc.syscall(0x40000000 | 41, 2, 1, 0)
assert result == -1 and ctypes.get_errno() == errno.EPERM, (result, ctypes.get_errno())
print('X32_SOCKET_REJECTED')
"""
    result = run_bounded([sys.executable, "-I", "-c", code], cwd=workdir, timeout=5)
    assert result.returncode == 0, result.output
    assert "X32_SOCKET_REJECTED" in result.output


@pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp support is verified in Docker")
def test_linux_seccomp_installation_self_test(tmp_path):
    assert seccomp_self_test()


@pytest.mark.skipif(sys.platform != "linux", reason="Seccomp architecture validation is Linux-specific")
def test_unsupported_seccomp_architecture_fails_closed(tmp_path):
    workdir = tmp_path / "unsupported-arch"
    workdir.mkdir()
    challenge = str(Path(__file__).parents[1].resolve())
    code = """
import platform, sys
sys.path.insert(0, sys.argv[1])
from unittest.mock import patch
from schrodinger.runtime.limits import install_child_syscall_filter
with patch.object(platform, 'machine', return_value='riscv64'):
    try:
        install_child_syscall_filter()
    except RuntimeError:
        print('UNSUPPORTED_ARCH_REJECTED')
    else:
        raise SystemExit('unsupported architecture accepted')
"""
    result = run_bounded([sys.executable, "-I", "-c", code, challenge], cwd=workdir, timeout=20)
    assert result.returncode == 0, result.output
    assert "UNSUPPORTED_ARCH_REJECTED" in result.output


@pytest.mark.skipif(sys.platform != "linux", reason="PR_SET_DUMPABLE is Linux-specific")
def test_linux_runtime_parent_procfs_memory_is_not_dumpable(tmp_path):
    workdir = tmp_path / "dumpable"
    workdir.mkdir()
    project = str(Path(__file__).parents[1].resolve())
    parent_code = """
import os, sys
sys.path.insert(0, sys.argv[1])
from schrodinger.runtime.limits import protect_runtime_parent
from schrodinger.runtime.executor import run_bounded
protect_runtime_parent()
child = \"import os; open(f'/proc/{os.getppid()}/environ','rb').read()\"
result = run_bounded([sys.executable, '-I', '-c', child], cwd=__import__('pathlib').Path(sys.argv[2]), timeout=5)
print('CHILD_RC=' + str(result.returncode))
print(result.output)
"""
    parent = subprocess.run(
        [sys.executable, "-c", parent_code, project, str(workdir)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert parent.returncode == 0, parent.stderr
    assert "CHILD_RC=1" in parent.stdout
    assert "PermissionError" in parent.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process-group termination is enforced in Docker")
def test_linux_timeout_terminates_descendants_in_original_process_group(tmp_path):
    workdir = tmp_path / "descendant-timeout"
    workdir.mkdir()
    code = "import os,time; pid=os.fork(); print(f'DESCENDANT_PID:{pid}',flush=True) if pid else None; time.sleep(30)"
    result = run_bounded([sys.executable, "-I", "-c", code], cwd=workdir, timeout=2.0)
    assert result.timed_out
    match = re.search(r"DESCENDANT_PID:(\d+)", result.output)
    assert match, result.output
    descendant_pid = int(match.group(1))
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{descendant_pid}/stat").read_text().split()[2]
        except FileNotFoundError:
            break
        if state == "Z":
            break
        time.sleep(0.05)
    else:
        pytest.fail("timed-out process left a live descendant")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux rlimits are verified by the Docker acceptance path")
def test_linux_child_receives_process_resource_limits(tmp_path):
    workdir = tmp_path / "limits"
    workdir.mkdir()
    result = run_bounded(
        [sys.executable, "-I", "-c", "import resource; print(resource.getrlimit(resource.RLIMIT_NOFILE)[0])"],
        cwd=workdir,
        timeout=5,
    )
    assert result.returncode == 0
    assert result.output.strip() == "64"
