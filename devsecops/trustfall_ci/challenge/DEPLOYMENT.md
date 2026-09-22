# Deployment and validation

Trustfall uses one application image with four role-selected services: `portal`, `scanner`, `agents`, and `release`. Compose gives them an isolated project network and scoped named volumes. Only `portal:8080` is published. `ollama` is a local-only profile service; production must provide an external or shared inference service at `OLLAMA_URL` with the exact `qwen2.5-coder:7b` model and digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`.

The `512Mi` metadata limit assumes that Qwen/Ollama is external to the challenge resource. A local 7B Ollama instance needs substantially more memory; measure the actual model cache and hardware before running local acceptance tests. Do not weaken or remove the mandatory Qwen check to fit the H7 limit.

## Local validation

From this directory:

```sh
docker compose --env-file .env --profile local build --no-cache
docker compose --env-file .env --profile local up --wait --build -d
python -m unittest discover -s tests -v
```

From `ai/trustfall_ci/` after the stack is healthy:

```sh
python solution/solve.py
```

The acceptance suite verifies service health, the pinned Trivy contract, the direct-release denial, one-run poisoning denial, durable assurance, fast review, candidate-bound approval, restart/reset behavior, isolated simultaneous Compose projects, and dynamic flags. Run the container suite with `OLLAMA_MODELS_PATH` set to the preloaded model directory.

Reset with:

```sh
docker compose --env-file .env --profile local down -v --remove-orphans
```

## Ship checks

- inspect `docker compose config` and confirm only `${PUBLIC_PORT}:8080` is published;
- inspect every service with `id` and confirm the runtime user is non-root;
- confirm `read_only`, `/tmp` tmpfs, `no-new-privileges`, and `cap_drop: ALL` remain enabled;
- confirm no service uses privileged mode, host networking, a Docker socket, or a host filesystem mount;
- inspect image history and the clean build context for `solution/`, `writeup/`, `handout/`, `.git/`, `flag.txt`, and event flag files;
- run two projects with distinct `INSTANCE_ID`, `INTERNAL_TOKEN`, `FLAG`, and `PUBLIC_PORT`, then verify repository, memory, approvals, and flags do not cross instance boundaries;
- simulate production with the same image and Compose configuration, replacing only local Ollama with the shared service;
- record observed startup and solver timing and host resource use for the exact Qwen cache and hardware.

## Anvil topology requirement

The challenge image intentionally selects one role from its command line. A deployment runner must therefore support the four internal role services, their private network, persistent portal/agent data, and an external/shared Qwen endpoint. The H7 metadata schema shown in `challenge.yml` describes one Docker image and one public port but has no fields for these internal role replicas or the inference dependency. If Anvil runs only a single container from `image`, this is a deployment blocker; do not collapse the roles or embed a model to work around it.
