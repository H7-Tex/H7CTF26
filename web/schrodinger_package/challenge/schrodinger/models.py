from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class ArtifactMetadata(BaseModel):
    artifact_id: str
    original_filename: str
    package_name: str
    version: str
    sha256: str
    size: int
    created_at: datetime
    source: str = "upload"


class PackageFile(BaseModel):
    path: str
    size: int
    sha256: str


class InspectionFinding(BaseModel):
    severity: str
    code: str
    message: str


class InspectionRecord(BaseModel):
    inspection_id: str
    artifact_id: str
    package_name: str
    version: str
    sha256: str
    status: str
    summary: str
    parsed_metadata: dict[str, str] = Field(default_factory=dict)
    findings: list[InspectionFinding]
    file_count: int
    created_at: datetime
    files: list[PackageFile] = Field(default_factory=list)


class InspectionSummary(BaseModel):
    inspection_id: str
    artifact_id: str
    package_name: str
    version: str
    sha256: str
    status: str
    summary: str
    parsed_metadata: dict[str, str] = Field(default_factory=dict)
    findings: list[InspectionFinding]
    file_count: int
    created_at: datetime


class PackageDetail(BaseModel):
    package: ArtifactMetadata
    latest_inspection: InspectionSummary | None


class InspectionHistory(BaseModel):
    latest: InspectionSummary | None
    items: list[InspectionSummary]


class InspectionList(BaseModel):
    items: list[InspectionSummary]
    total: int


class RuntimeJob(BaseModel):
    job_id: str
    artifact_id: str
    package_name: str
    version: str
    sha256: str
    status: str
    created_at: datetime
    duration_ms: int
    output: list[str]


class RuntimeJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class InternalRuntimeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    inspection_id: str = Field(min_length=1, max_length=128)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RuntimeResult(BaseModel):
    artifact_id: str
    inspection_id: str
    sha256: str
    installer_sha256: str
    module_path: str
    archive_occurrences: int
    selected_sha256: str
    installed_sha256: str
    import_succeeded: bool
    status: str
    duration_ms: int
    output: list[str]


class RuntimeJobResponse(RuntimeJob):
    """Immediate Portal response; flag is transient and never persisted."""

    flag: str | None = None
