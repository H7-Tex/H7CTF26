# Echo Chamber

Author: H7CTF  
Category: AI  
Difficulty: Medium

Atlas Incident Intelligence is an incident research platform. Investigate its open incident and the technical knowledge available to analysts.

## Deployment configuration

The application defaults to the authoritative H7CTF Qwen service and model:

```text
QWEN_BASE_URL=https://qwen.h7tex.com
QWEN_MODEL=Qwen2.5-Coder-7B-Instruct
```

`challenge/docker-compose.yml` passes these defaults to the container. Operators may set the same variables in the deployment environment. Set `FLAG` externally; it is added only to the deep forensic report generated after corroboration. Do not store secrets or service credentials in the repository. The Qwen service does not require an authentication setting here.

To start the container, provide the flag through your deployment environment and run:

```sh
cd challenge
docker compose up --build
```

The application timeout is configurable with `QWEN_TIMEOUT_SECONDS` and defaults to 60 seconds. Keep the default unless deployment validation shows that normal Qwen requests need more time. Inference failures remain transport/application errors and do not fall back to another model.

## Validation

Run deterministic tests from `challenge/`:

```sh
python -m unittest discover -s tests -v
```

The deployment-model semantic matrix is authoritative only against `https://qwen.h7tex.com` with `Qwen2.5-Coder-7B-Instruct`. From PowerShell, run the operator-only launcher:

```powershell
.\scripts\deployment_semantic_matrix.ps1
```

It pins the deployment endpoint and model, enables live acceptance, and runs five trials. Deployment-model semantic matrix: pending until this launcher has been run against that service.

## Optional local development with Ollama

Local Ollama is for development smoke testing only. It is not the semantic validation target for deployment. From PowerShell:

```powershell
cd challenge
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
.\dev-local-ollama.ps1
```

The launcher uses the Windows Ollama service at `http://127.0.0.1:11434`, model `qwen2.5-coder:7b`, and a 300-second local timeout. To run the minimal development smoke, use the same local configuration and run `python scripts/local_qwen_smoke.py` from `challenge/`. Local semantic results are diagnostic only; a false seeded corroboration or a failed intended classification does not fail the smoke by itself. Its integration and pipeline checks still must pass.

For the smoke in a separate PowerShell session, set the local endpoint and model before running:

```powershell
$env:QWEN_BASE_URL = "http://127.0.0.1:11434"
$env:QWEN_MODEL = "qwen2.5-coder:7b"
$env:QWEN_TIMEOUT_SECONDS = "300"
python scripts/local_qwen_smoke.py
```
