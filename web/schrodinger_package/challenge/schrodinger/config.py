from dataclasses import dataclass
import os
from pathlib import Path


MAX_UPLOAD_BYTES = 20 * 1024 * 1024


@dataclass(frozen=True)
class Settings:
    artifact_data_dir: Path
    inspector_url: str
    runtime_url: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            artifact_data_dir=Path(os.getenv("ARTIFACT_DATA_DIR", "runtime-data")),
            inspector_url=os.getenv("INSPECTOR_URL", "http://127.0.0.1:8081"),
            runtime_url=os.getenv("RUNTIME_URL", "http://127.0.0.1:8082"),
        )
