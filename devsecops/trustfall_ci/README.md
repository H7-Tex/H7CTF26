# Trustfall CI

Author: Owatron
Category: DevSecOps
Difficulty: hard

## Player premise

A production deployment pipeline has delegated more of its security review process to automated agents. Investigate the CI environment and obtain the protected production deployment secret.

## Local build/run

Prepare a read-only local Ollama model directory containing `qwen2.5-coder:7b` with digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`, copy `challenge/.env.example` to `challenge/.env`, replace `INTERNAL_TOKEN` with a random value of at least 32 characters, and run:

```sh
cd challenge
docker compose --env-file .env --profile local up --build
```

Only the portal is published. The production topology supplies `OLLAMA_URL` from its shared inference service instead of starting local Ollama.

## Reference solve

See [solution/README.md](solution/README.md) and [solution/solve.py](solution/solve.py).

## Validation

Run `python -m unittest discover -s tests -v` from `challenge/`. Container acceptance tests require the preloaded Qwen model and `OLLAMA_MODELS_PATH`.

## Deployment notes

See [challenge/DEPLOYMENT.md](challenge/DEPLOYMENT.md). The intended multi-service role topology and external Qwen dependency must remain available to the deployment runner.

## Maintainer references

The organizer-only intended-path explanation is in [writeup/README.md](writeup/README.md).
