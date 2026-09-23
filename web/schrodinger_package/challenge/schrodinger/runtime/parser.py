"""Runtime-owned wheel resolution, independent from Inspector interpretation."""

from dataclasses import dataclass
import hashlib
from io import BytesIO
import zipfile

from packaging.utils import canonicalize_name


@dataclass(frozen=True)
class ResolvedModule:
    module_name: str
    path: str
    sha256: str
    occurrences: int

    @property
    def shadowed(self) -> bool:
        return self.occurrences > 1


def default_module_name(distribution: str) -> str:
    """Map the wheel distribution to the registry's import convention."""
    return str(canonicalize_name(distribution)).replace("-", "_")


def resolve_module(content: bytes, distribution: str) -> ResolvedModule:
    """Resolve the last matching module entry, as the installer does."""
    module_name = default_module_name(distribution)
    if not module_name.isidentifier():
        raise ValueError("package name does not map to a valid module")
    path = f"{module_name}/__init__.py"
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            entries = [info for info in archive.infolist() if info.filename == path and not info.is_dir()]
            if not entries:
                raise ValueError(f"wheel does not contain the runtime module {path}")
            selected = entries[-1]
            if selected.file_size > 64 * 1024 * 1024:
                raise ValueError("runtime module exceeds the installation limit")
            with archive.open(selected) as member:
                digest = hashlib.sha256()
                while block := member.read(1024 * 1024):
                    digest.update(block)
            return ResolvedModule(module_name, path, digest.hexdigest(), len(entries))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ValueError("runtime could not resolve the wheel module") from exc
