$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$env:QWEN_BASE_URL = "https://qwen.h7tex.com"
$env:QWEN_MODEL = "Qwen2.5-Coder-7B-Instruct"
$env:RUN_QWEN_ACCEPTANCE = "1"
$env:QWEN_ACCEPTANCE_RUNS = "5"

python tests/semantic_acceptance.py
exit $LASTEXITCODE
