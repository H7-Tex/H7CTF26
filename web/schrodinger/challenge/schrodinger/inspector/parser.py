"""Inspector-owned parser for ordinary, valid Python wheel archives."""

from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default
import hashlib
from io import BytesIO
from pathlib import PurePosixPath
import zipfile

from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from schrodinger.models import InspectionFinding, PackageFile


MAX_FILES = 5_000
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024


@dataclass
class WheelInspection:
    status: str
    summary: str
    parsed_metadata: dict[str, str]
    findings: list[InspectionFinding]
    files: list[PackageFile]


def inspect_wheel(filename: str, content: bytes) -> WheelInspection:
    findings: list[InspectionFinding] = []
    files: list[PackageFile] = []

    try:
        distribution, wheel_version, _, _ = parse_wheel_filename(filename)
        with zipfile.ZipFile(BytesIO(content)) as archive:
            raw_entries = [entry for entry in archive.infolist() if not entry.is_dir()]
            if not raw_entries:
                raise ValueError("The wheel archive contains no files.")
            if len(raw_entries) > MAX_FILES:
                raise ValueError("The wheel contains too many files for inspection.")
            if sum(entry.file_size for entry in raw_entries) > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("The uncompressed package contents exceed the inspection limit.")
            if any(entry.flag_bits & 1 for entry in raw_entries):
                raise ValueError("Encrypted package members cannot be inspected.")
            if any(
                "\\" in entry.filename
                or ":" in entry.filename
                or entry.filename.startswith("/")
                or PurePosixPath(entry.filename).as_posix() != entry.filename
                or any(part in {".", ".."} for part in entry.filename.split("/"))
                for entry in raw_entries
            ):
                raise ValueError("The wheel contains an invalid archive path.")

            # Deliberate Phase 2 differential: for the import package only, the
            # Inspector collapses repeats to the first entry; Runtime uses last.
            import_path = f"{str(canonicalize_name(str(distribution))).replace('-', '_')}/__init__.py"
            grouped_entries = {}
            for entry in archive.infolist():
                if not entry.is_dir():
                    grouped_entries.setdefault(entry.filename, []).append(entry)
            if any(len(group) > 1 and path != import_path for path, group in grouped_entries.items()):
                raise ValueError("The wheel contains conflicting archive records.")
            entries_by_name = {path: group[0] for path, group in grouped_entries.items()}
            entries = list(entries_by_name.values())

            dist_info = f"{str(distribution).replace('-', '_')}-{wheel_version}.dist-info"
            metadata_path = f"{dist_info}/METADATA"
            wheel_path = f"{dist_info}/WHEEL"
            record_path = f"{dist_info}/RECORD"
            metadata_paths = [metadata_path] if metadata_path in entries_by_name else [
                entry.filename for entry in entries if entry.filename.endswith(".dist-info/METADATA")
            ]
            wheel_paths = [wheel_path] if wheel_path in entries_by_name else [
                entry.filename for entry in entries if entry.filename.endswith(".dist-info/WHEEL")
            ]
            record_paths = [record_path] if record_path in entries_by_name else [
                entry.filename for entry in entries if entry.filename.endswith(".dist-info/RECORD")
            ]
            if len(metadata_paths) != 1 or len(wheel_paths) != 1 or len(record_paths) != 1:
                raise ValueError("The wheel must contain one METADATA, WHEEL, and RECORD file.")

            metadata_entry = entries_by_name[metadata_paths[0]]
            if metadata_entry.file_size > MAX_METADATA_BYTES:
                raise ValueError("Package metadata exceeds the inspection limit.")
            with archive.open(metadata_entry) as member:
                metadata_bytes = member.read(MAX_METADATA_BYTES + 1)
            if len(metadata_bytes) > MAX_METADATA_BYTES:
                raise ValueError("Package metadata exceeds the inspection limit.")
            metadata = BytesParser(policy=default).parsebytes(metadata_bytes)
            if not metadata.get("Name") or not metadata.get("Version"):
                raise ValueError("Package metadata must include a name and version.")
            if canonicalize_name(metadata["Name"]) != canonicalize_name(str(distribution)):
                raise ValueError("Package metadata name does not match the wheel filename.")
            if Version(metadata["Version"]) != wheel_version:
                raise ValueError("Package metadata version does not match the wheel filename.")

            total_read = 0
            for entry in entries:
                digest = hashlib.sha256()
                size = 0
                with archive.open(entry) as member:
                    while block := member.read(1024 * 1024):
                        size += len(block)
                        total_read += len(block)
                        if total_read > MAX_UNCOMPRESSED_BYTES:
                            raise ValueError("The uncompressed package contents exceed the inspection limit.")
                        digest.update(block)
                if size != entry.file_size:
                    raise ValueError("A package member did not match its declared size.")
                files.append(PackageFile(path=entry.filename, size=size, sha256=digest.hexdigest()))

            if not metadata.get("License-Expression") and not metadata.get("License"):
                findings.append(
                    InspectionFinding(
                        severity="info",
                        code="license_metadata_absent",
                        message="The package metadata does not declare a license.",
                    )
                )
            visible_hooks = sorted({
                entry.filename for entry in entries
                if entry.filename.lower().endswith(".pth")
                or entry.filename.lower().rsplit("/", 1)[-1] in {"sitecustomize.py", "usercustomize.py"}
                or ".data/scripts/" in entry.filename.lower()
            })
            if visible_hooks:
                findings.append(
                    InspectionFinding(
                        severity="warning",
                        code="runtime_hook_visible",
                        message=f"Potential package hooks are visible: {', '.join(visible_hooks[:10])}.",
                    )
                )
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        return WheelInspection(
            status="rejected",
            summary="The package did not meet the wheel inspection requirements.",
            parsed_metadata={},
            findings=[InspectionFinding(severity="error", code="wheel_invalid", message=str(exc))],
            files=[],
        )

    status = "passed_with_advisories" if findings else "passed"
    summary = "Package metadata and file inventory recorded."
    if findings:
        summary = "Package passed required checks with informational metadata findings."
    parsed_metadata = {
        key: str(metadata[key])
        for key in ("Name", "Version", "Summary", "License-Expression", "License", "Requires-Python")
        if metadata.get(key)
    }
    parsed_metadata["Visible-Runtime-Hooks"] = ", ".join(visible_hooks[:10]) if visible_hooks else "none detected"
    return WheelInspection(status=status, summary=summary, parsed_metadata=parsed_metadata, findings=findings, files=files)
