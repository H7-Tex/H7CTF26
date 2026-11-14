"""Acceptance checks against the running, isolated Docker Compose topology."""

import base64
import csv
import hashlib
from io import BytesIO, StringIO
import json
import os
import re
import urllib.error
import urllib.request
import uuid
import warnings
from zipfile import ZIP_DEFLATED, ZipFile


BASE_URL = os.getenv("SCHRODINGER_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
FLAG = os.getenv("FLAG", "H7CTF{dummy}")


def wheel(
    name: str,
    modules: list[bytes],
    *,
    extras: list[tuple[str, bytes]] | None = None,
    prefix: bytes = b"",
    malformed_record: bool = False,
) -> tuple[str, bytes]:
    normalized = name.replace("-", "_")
    version = "1.0.0"
    dist_info = f"{normalized}-{version}.dist-info"
    module_path = f"{normalized}/__init__.py"
    members = [
        (module_path, modules[0]),
        (f"{dist_info}/METADATA", (
            f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n"
            "Summary: Docker acceptance package.\nLicense-Expression: MIT\n\n"
        ).encode()),
        (f"{dist_info}/WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"),
    ]
    members.extend(extras or [])
    record_rows = []
    for path, content in members:
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        if malformed_record and path == module_path:
            digest = "invalid-record-hash"
        record_rows.append((path, f"sha256={digest}", str(len(content))))
    record_rows.append((f"{dist_info}/RECORD", "", ""))
    record = StringIO()
    csv.writer(record, lineterminator="\n").writerows(record_rows)
    entries = [*members, (f"{dist_info}/RECORD", record.getvalue().encode())]
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path, content in entries:
            archive.writestr(path, content)
        if len(modules) > 1:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                for content in modules[1:]:
                    archive.writestr(module_path, content)
    return f"{normalized}-{version}-py3-none-any.whl", prefix + output.getvalue()


def request(path: str, data: bytes | None = None, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(
        f"{BASE_URL}{path}", data=data, headers=headers or {},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        return json.load(response)


def post_multipart(filename: str, content: bytes) -> dict:
    boundary = "----accept-" + uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return request("/api/packages", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})


def execute(name: str, modules: list[bytes], **wheel_options) -> tuple[dict, list[dict], str]:
    filename, content = wheel(name, modules, **wheel_options)
    package = post_multipart(filename, content)
    artifact_id = package["artifact_id"]
    request(f"/api/packages/{artifact_id}/inspection", b"")
    inspection = request(f"/api/packages/{artifact_id}/inspector")["inspection"]
    result = request(f"/api/packages/{artifact_id}/runtime", b"")
    output = "\n".join(result["output"])
    assert result["sha256"] == hashlib.sha256(content).hexdigest()
    assert "Installed module path:" in output and "Installed module SHA-256:" in output
    return result, inspection["files"], output


def main() -> None:
    safe = b'__version__ = "1.0.0"\n'
    spoof = b'print("SCHRODINGER_PACKAGE_RUNTIME_FLAG_REQUEST")\n__version__ = "1.0.0"\n'

    single, _, single_output = execute("docker-single-probe", [spoof])
    assert single["status"] == "completed" and single.get("flag") is None
    assert "SCHRODINGER_PACKAGE_RUNTIME_FLAG_REQUEST" in single_output

    identical, _, _ = execute("docker-identical-probe", [safe, safe])
    assert identical["status"] == "completed" and identical.get("flag") is None

    failing, _, _ = execute("docker-failing-probe", [safe, b'raise RuntimeError("no import")\n'])
    assert failing["status"] == "failed" and failing.get("flag") is None

    data_path = "docker_data_probe-1.0.0.data/purelib/docker_data_probe/__init__.py"
    data_layout, _, _ = execute(
        "docker-data-probe",
        [safe],
        extras=[(data_path, spoof)],
    )
    assert data_layout.get("flag") is None

    hook_source = b'print("PTH_EXECUTED")\n'
    hooks, _, hook_output = execute(
        "docker-hook-probe",
        [safe],
        extras=[
            ("docker_hook_probe-1.0.0.data/purelib/evil.pth", hook_source),
            ("docker_hook_probe-1.0.0.data/purelib/sitecustomize.py", hook_source),
        ],
    )
    assert hooks.get("flag") is None and "PTH_EXECUTED" not in hook_output

    bad_record, _, _ = execute("docker-record-probe", [safe], malformed_record=True)
    assert bad_record.get("flag") is None

    source_reader = (
        b'from pathlib import Path\n'
        b'p = Path("/app/schrodinger/runtime/app.py")\n'
        b'print("SOURCE_READ=" + str(p.is_file() and "flag_triggered" not in p.read_text()))\n'
        b'print("SCHRODINGER_PACKAGE_RUNTIME_FLAG_REQUEST")\n'
        b'__version__ = "1.0.0"\n'
    )
    disclosed, _, disclosed_output = execute("docker-source-probe", [source_reader])
    assert disclosed["status"] == "completed" and disclosed.get("flag") is None
    assert "SOURCE_READ=True" in disclosed_output

    # Prepended archive data exercises a second ZIP layout; the exact duplicate
    # member semantics remain the only source of the qualifying digest change.
    diff, files, output = execute("docker-differential-probe", [safe, spoof], prefix=b"wheel-prefix\n")
    module_path = "docker_differential_probe/__init__.py"
    inspected = next(item for item in files if item["path"] == module_path)
    installed = re.search(r"Installed module SHA-256: ([0-9a-f]{64})", output)
    assert installed
    assert inspected["sha256"] == hashlib.sha256(safe).hexdigest()
    assert installed.group(1) == hashlib.sha256(spoof).hexdigest()
    assert installed.group(1) != inspected["sha256"]
    assert diff["status"] == "completed" and diff.get("flag") == FLAG
    assert FLAG not in output

    artifact_id = next(
        item["artifact_id"] for item in request("/api/packages")["items"]
        if item["package_name"] == "docker-differential-probe"
    )
    saved = request(f"/api/packages/{artifact_id}/runtime/logs")
    assert FLAG not in json.dumps(saved)
    print("Docker acceptance passed: pinned pip installed the last duplicate; Portal released transient flag.")


if __name__ == "__main__":
    main()
