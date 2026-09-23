"""Negative coverage for alternate ZIP and wheel metadata structures."""

from io import BytesIO
import warnings
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from schrodinger.inspector.parser import inspect_wheel
from test_portal import wheel_bytes


def append_member(payload: bytes, path: str, content: bytes) -> bytes:
    output = BytesIO()
    with ZipFile(BytesIO(payload)) as source, ZipFile(output, "w", ZIP_DEFLATED) as target:
        for entry in source.infolist():
            target.writestr(entry, source.read(entry))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            target.writestr(path, content)
    return output.getvalue()


@pytest.mark.parametrize("member", ["METADATA", "WHEEL", "RECORD"])
def test_duplicate_distribution_metadata_records_are_rejected_generically(member):
    filename, payload = "astra_probe-1.2.3-py3-none-any.whl", wheel_bytes("astra-probe", "1.2.3")
    path = f"astra_probe-1.2.3.dist-info/{member}"
    content = b"conflicting record\n"
    result = inspect_wheel(filename, append_member(payload, path, content))
    assert result.status == "rejected"
    assert "conflicting archive records" in result.findings[0].message.lower()
    assert "import package path" not in result.findings[0].message.lower()


@pytest.mark.parametrize("path", [
    "../astra_probe/__init__.py",
    "./astra_probe/__init__.py",
    ".//astra_probe/__init__.py",
    "astra_probe\\__init__.py",
    "/astra_probe/__init__.py",
])
def test_noncanonical_and_traversal_archive_paths_are_rejected(path):
    filename, payload = "astra_probe-1.2.3-py3-none-any.whl", wheel_bytes("astra-probe", "1.2.3")
    result = inspect_wheel(filename, append_member(payload, path, b"__version__ = '1.2.3'\n"))
    assert result.status == "rejected"
    assert "invalid archive path" in result.findings[0].message.lower()
