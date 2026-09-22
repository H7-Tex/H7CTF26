# Reference solution

## Requirements

- Docker Compose
- Python 3.12 with `httpx`
- A fresh Trustfall instance
- The mandatory `qwen2.5-coder:7b` Ollama model with digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`

## Start a fresh local instance

From `ai/trustfall_ci/challenge/`, copy `.env.example` to `.env`, set `OLLAMA_MODELS_PATH` to the read-only directory containing the required model, replace `INTERNAL_TOKEN` with a random value of at least 32 characters, and start:

```sh
docker compose --env-file .env --profile local up --build -d
```

The example environment uses `H7CTF{dummy}`. Production flags are injected through `FLAG` and must never be committed.

## Run the solver

From `ai/trustfall_ci/`, run:

```sh
python solution/solve.py
```

The expected result is `H7CTF{dummy}` after the intended two-stage review and release sequence completes.

## Reset

From `ai/trustfall_ci/challenge/`, reset all state and solve again:

```sh
docker compose --env-file .env --profile local down -v
docker compose --env-file .env --profile local up --build -d
```
