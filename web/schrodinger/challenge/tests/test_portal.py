import hashlib
import asyncio
from io import BytesIO
import sqlite3
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi.testclient import TestClient
import httpx
import pytest
from packaging.utils import canonicalize_name
from packaging.version import Version

from schrodinger.config import Settings
from schrodinger.inspector.app import create_app as create_inspector_app
from schrodinger.portal.app import create_app
from schrodinger.store import ArtifactStore


def wheel_bytes(name="example-package", version="1.2.3", license_name="MIT"):
    normalized = name.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\nSummary: An example package.\nLicense-Expression: {license_name}\n\n"
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr(f"{normalized}/__init__.py", "__version__ = '1.2.3'\n")
        archive.writestr(f"{dist_info}/METADATA", metadata)
        archive.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n")
        archive.writestr(f"{dist_info}/RECORD", "")
    return output.getvalue()


def test_upload_records_digest_and_preserves_bytes(tmp_path):
    payload = wheel_bytes()
    client = TestClient(create_app(tmp_path), raise_server_exceptions=False)
    response = client.post("/api/v1/packages", files={"file": ("example_package-1.2.3-py3-none-any.whl", payload)})

    assert response.status_code == 201
    metadata = response.json()
    assert metadata["sha256"] == hashlib.sha256(payload).hexdigest()
    assert metadata["size"] == len(payload)
    assert metadata["package_name"] == "example-package"
    assert metadata["version"] == "1.2.3"
    assert metadata["created_at"].endswith("Z")
    assert client.app.state.store.read_bytes(metadata["artifact_id"]) == payload
    with sqlite3.connect(tmp_path / "metadata.sqlite3") as db:
        row = db.execute("SELECT original_filename, sha256, size FROM artifacts WHERE artifact_id = ?", (metadata["artifact_id"],)).fetchone()
    assert row == ("example_package-1.2.3-py3-none-any.whl", hashlib.sha256(payload).hexdigest(), len(payload))


def test_existing_artifact_cannot_be_overwritten(tmp_path):
    payload = wheel_bytes()
    client = TestClient(create_app(tmp_path), raise_server_exceptions=False)
    with patch("schrodinger.store.uuid.uuid4") as uuid4:
        uuid4.return_value.hex = "a" * 32
        first = client.post("/api/v1/packages", files={"file": ("first-1.0-py3-none-any.whl", payload)})
        second = client.post("/api/v1/packages", files={"file": ("second-1.0-py3-none-any.whl", wheel_bytes("second"))})

    assert first.status_code == 201
    assert second.status_code == 409
    assert client.app.state.store.read_bytes("a" * 32) == payload


def test_non_wheel_and_non_zip_uploads_are_rejected(tmp_path):
    client = TestClient(create_app(tmp_path))
    extension = client.post("/api/v1/packages", files={"file": ("example.zip", wheel_bytes())})
    content = client.post("/api/v1/packages", files={"file": ("example-1.0-py3-none-any.whl", b"not a ZIP")})
    assert extension.status_code == 415
    assert content.status_code == 415


def test_invalid_pep427_wheel_filenames_are_rejected(tmp_path):
    client = TestClient(create_app(tmp_path))
    for filename in ("example-package-1.0-py3-none.whl", "bad name-1.0-py3-none-any.whl"):
        response = client.post("/api/v1/packages", files={"file": (filename, wheel_bytes())})
        assert response.status_code == 422


def test_artifact_store_persists_supplied_identity_without_parsing_filename(tmp_path):
    store = ArtifactStore(tmp_path)
    artifact = store.create(
        "not-a-wheel-filename.txt",
        b"unchanged upload bytes",
        package_name="supplied-name",
        version="1.2.3",
    )

    assert (artifact.package_name, artifact.version) == ("supplied-name", "1.2.3")
    assert store.read_bytes(artifact.artifact_id) == b"unchanged upload bytes"


def test_upload_size_is_limited(tmp_path):
    client = TestClient(create_app(tmp_path))
    payload = b"x" * (20 * 1024 * 1024 + 1)
    response = client.post("/api/v1/packages", files={"file": ("large-1.0-py3-none-any.whl", payload)})
    assert response.status_code == 413, response.text


def test_portal_checks_internal_services(tmp_path, monkeypatch):
    seen = []

    def internal_service(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"status": "ok"})

    original = httpx.AsyncClient

    class InternalClient(original):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(internal_service)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", InternalClient)
    settings = Settings(tmp_path, "http://inspector:8081", "http://runtime:8082")
    response = TestClient(create_app(settings=settings)).get("/health")
    assert response.status_code == 200
    assert seen == ["http://inspector:8081/health", "http://runtime:8082/health"]


def test_inspection_uses_stored_bytes_and_records_the_upload_digest(tmp_path, monkeypatch):
    inspector = create_inspector_app(tmp_path)
    original_client = httpx.AsyncClient

    class InspectorClient(original_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.ASGITransport(app=inspector)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", InspectorClient)
    client = TestClient(create_app(tmp_path, Settings(tmp_path, "http://inspector:8081", "http://runtime:8082")))
    payload = wheel_bytes("My.Pkg", "1.0.0")
    with patch("schrodinger.store.uuid.uuid4") as uuid4:
        uuid4.return_value.hex = "b" * 32
        uploaded = client.post("/api/v1/packages", files={"file": ("My_Pkg-1.0-py3-none-any.whl", payload)})
        artifact_id = uploaded.json()["artifact_id"]
        inspected = client.post(f"/api/v1/packages/{artifact_id}/inspection")

        replacement = client.post("/api/v1/packages", files={"file": ("replacement-1.0-py3-none-any.whl", wheel_bytes("replacement", "1.0.0"))})

    assert uploaded.status_code == 201
    assert inspected.status_code == 201
    inspection = inspected.json()
    assert inspection["sha256"] == hashlib.sha256(payload).hexdigest()
    assert inspection["artifact_id"] == artifact_id
    assert inspection["package_name"] == "my-pkg"
    assert canonicalize_name(inspection["parsed_metadata"]["Name"]) == inspection["package_name"]
    assert inspection["version"] == "1.0"
    assert Version(inspection["version"]) == Version(inspection["parsed_metadata"]["Version"])
    assert inspection["status"] == "passed"
    assert inspection["file_count"] == 4
    assert "files" not in inspection
    assert replacement.status_code == 409
    assert client.app.state.store.read_bytes(artifact_id) == payload

    detail = client.get(f"/api/v1/packages/{artifact_id}").json()
    history = client.get(f"/api/v1/packages/{artifact_id}/inspection").json()
    all_inspections = client.get("/api/v1/inspections").json()
    manifest = client.get(f"/api/v1/packages/{artifact_id}/manifest").json()
    assert "files" not in detail["latest_inspection"]
    assert "files" not in history["latest"]
    assert all("files" not in item for item in history["items"])
    assert all("files" not in item for item in all_inspections["items"])
    assert len(manifest["files"]) == inspection["file_count"]
    assert manifest["sha256"] == hashlib.sha256(payload).hexdigest()

    rerun = client.post(f"/api/v1/packages/{artifact_id}/inspection")
    assert rerun.status_code == 201
    assert "files" not in rerun.json()
    assert len(client.get(f"/api/v1/packages/{artifact_id}/inspection").json()["items"]) == 2

    with sqlite3.connect(tmp_path / "metadata.sqlite3") as db:
        row = db.execute("SELECT sha256 FROM inspections WHERE artifact_id = ?", (artifact_id,)).fetchone()
    assert row == (hashlib.sha256(payload).hexdigest(),)


@pytest.mark.parametrize("path", ["/api/packages", "/api/v1/packages"])
def test_upload_body_limit_rejects_large_chunked_requests(tmp_path, path):
    client = TestClient(create_app(tmp_path), raise_server_exceptions=False)
    prefix = (
        b"--testboundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="large-1.0-py3-none-any.whl"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
    )
    payload = prefix + b"x" * (20 * 1024 * 1024 + 128 * 1024) + b"\r\n--testboundary--\r\n"

    async def body_stream():
        chunk_size = 32 * 1024
        for offset in range(0, len(payload), chunk_size):
            yield payload[offset:offset + chunk_size]

    async def send():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=client.app), base_url="http://testserver"
        ) as async_client:
            return await async_client.post(
                path,
                content=body_stream(),
                headers={"content-type": "multipart/form-data; boundary=testboundary"},
            )

    response = asyncio.run(send())
    assert response.status_code == 413, response.text


@pytest.mark.parametrize("path", ["/api/packages", "/api/v1/packages"])
def test_upload_content_length_limit_rejects_before_body_parser(tmp_path, path):
    from schrodinger.portal.middleware import UploadLimitMiddleware

    client = TestClient(create_app(tmp_path), raise_server_exceptions=False)
    response = client.post(
        path,
        content=b"x",
        headers={
            "content-type": "multipart/form-data; boundary=unused",
            "content-length": str(UploadLimitMiddleware.max_request_bytes + 1),
        },
    )
    assert response.status_code == 413, response.text


def test_inspector_rejects_missing_wheel_metadata(tmp_path):
    inspector = TestClient(create_inspector_app(tmp_path), raise_server_exceptions=False)
    with TestClient(create_app(tmp_path)) as portal:
        payload = BytesIO()
        with ZipFile(payload, "w") as archive:
            archive.writestr("hello.txt", "hello")
        uploaded = portal.post("/api/v1/packages", files={"file": ("sample-1.0-py3-none-any.whl", payload.getvalue())})
        result = inspector.post("/inspections", json={"artifact_id": uploaded.json()["artifact_id"]})
    assert result.status_code == 201
    assert result.json()["status"] == "rejected"


def test_seeded_registry_and_read_apis(tmp_path):
    client = TestClient(create_app(tmp_path))
    packages = client.get("/api/v1/packages").json()
    inspections = client.get("/api/v1/inspections").json()
    jobs = client.get("/api/v1/runtime/jobs").json()

    assert packages["total"] == 4
    assert inspections["total"] == 4
    assert jobs["total"] == 3
    assert client.get("/api/v1/policy").status_code == 200
    assert client.get(f"/api/v1/runtime/jobs/{jobs['items'][0]['job_id']}").status_code == 200
