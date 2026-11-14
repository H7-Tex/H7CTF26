$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$env:QWEN_BASE_URL = "http://127.0.0.1:11434"
$env:QWEN_MODEL = "qwen2.5-coder:7b"
$env:QWEN_TIMEOUT_SECONDS = "300"
$env:DATA_DIR = Join-Path $PSScriptRoot "data"

python -m uvicorn echo_chamber.main:app --host 127.0.0.1 --port 8080
