"""Small, harmless package catalog used by a fresh challenge instance."""

import base64
import csv
import hashlib
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO
from zipfile import ZIP_DEFLATED, ZipFile
from packaging.utils import canonicalize_name

from schrodinger.models import InspectionFinding, InspectionRecord, PackageFile, RuntimeJob
from schrodinger.store import ArtifactStore


PACKAGES = (
    ("astra-http-client", "3.2.1", "2026-09-19T08:20:00+00:00", "MIT", "HTTP helpers for internal Python services."),
    ("astra-metrics", "1.8.4", "2026-09-16T14:05:00+00:00", "Apache-2.0", "Metrics adapters for application services."),
    ("astra-log-format", "0.9.7", "2026-09-10T11:40:00+00:00", "", "Structured logging helpers."),
    ("astra-auth-client", "2.4.0", "2026-09-04T09:15:00+00:00", "BSD-3-Clause", "Client library for the internal identity service."),
)


def wheel_bytes(name: str, version: str, license_name: str, summary: str) -> tuple[str, bytes]:
    normalized = name.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    filename = f"{normalized}-{version}-py3-none-any.whl"
    metadata = f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\nSummary: {summary}\n"
    if license_name:
        metadata += f"License-Expression: {license_name}\n"
    metadata += "\n"
    members = {
        f"{normalized}/__init__.py": f'"""{summary}"""\n__version__ = "{version}"\n'.encode(),
        f"{dist_info}/METADATA": metadata.encode(),
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: astra-package-service\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
    }
    record_path = f"{dist_info}/RECORD"
    rows = []
    for path, content in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        rows.append((path, f"sha256={digest}", str(len(content))))
    rows.append((record_path, "", ""))
    buffer = StringIO()
    csv.writer(buffer, lineterminator="\n").writerows(rows)
    members[record_path] = buffer.getvalue().encode()

    # Build in memory as bytes, without extracting or executing package code.
    archive_data = BytesIO()
    with ZipFile(archive_data, "w", ZIP_DEFLATED) as archive:
        for path, content in members.items():
            archive.writestr(path, content)
    return filename, archive_data.getvalue()


def seed_platform(store: ArtifactStore) -> None:
    if not any(item.source == "seed" for item in store.list_artifacts(limit=10_000)):
        for index, (name, version, timestamp, license_name, summary) in enumerate(PACKAGES):
            filename, content = wheel_bytes(name, version, license_name, summary)
            created_at = datetime.fromisoformat(timestamp)
            artifact = store.create(
                filename, content, package_name=name, version=version,
                source="seed", created_at=created_at,
            )
            with ZipFile(BytesIO(content)) as archive:
                files = []
                for path in archive.namelist():
                    data = archive.read(path)
                    files.append(PackageFile(path=path, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
            findings = []
            status = "passed"
            if not license_name:
                findings.append(
                    InspectionFinding(
                        severity="info",
                        code="license_metadata_absent",
                        message="The package metadata does not declare a license.",
                    )
                )
                status = "passed_with_advisories"
            inspected_at = created_at + timedelta(minutes=12 + index * 7)
            store.record_inspection(
                InspectionRecord(
                    inspection_id=f"seed-inspection-{index + 1:03d}",
                    artifact_id=artifact.artifact_id,
                    package_name=name,
                    version=version,
                    sha256=artifact.sha256,
                    status=status,
                    summary="Package contents recorded; baseline metadata checks completed.",
                    parsed_metadata={
                        "Name": name,
                        "Version": version,
                        "Summary": summary,
                        **({"License-Expression": license_name} if license_name else {}),
                    },
                    findings=findings,
                    file_count=len(files),
                    created_at=inspected_at,
                    files=files,
                )
            )

    packages = {item.package_name: item for item in store.list_artifacts(limit=10_000)}
    for index, (name, status, when, duration) in enumerate(
        (
            ("astra-http-client", "completed", "2026-09-20T10:31:00+00:00", 842),
            ("astra-metrics", "completed", "2026-09-18T15:42:00+00:00", 691),
            ("astra-log-format", "completed", "2026-09-12T08:17:00+00:00", 917),
        )
    ):
        artifact = packages[name]
        module_path = f"{str(canonicalize_name(name)).replace('-', '_')}/__init__.py"
        inspection = store.inspections(artifact.artifact_id, limit=1)[0]
        module = next(item for item in inspection.files if item.path == module_path)
        output = [
            "Environment created",
            f"Installed module path: {module_path}",
            f"Installed module SHA-256: {module.sha256}",
            "Import check completed",
            "Session closed",
        ]
        store.seed_runtime_job(
            RuntimeJob(
                job_id=f"run-{index + 1:04d}-baseline",
                artifact_id=artifact.artifact_id,
                package_name=name,
                version=artifact.version,
                sha256=artifact.sha256,
                status=status,
                created_at=datetime.fromisoformat(when),
                duration_ms=duration,
                output=output,
            )
        )
