# Local challenge environment

From this directory, run `docker compose up --build --wait`. Portal is available
at `http://localhost:8080`; Inspector and Runtime have no published ports.
Compose mounts `flag.txt` into Portal only. That file contains a dummy local
value. To use another local flag, copy `.env.example` to `.env.local`, replace
the value, and start Compose with `docker compose --env-file .env.local up
--build --wait`. Never commit `.env.local` or place deployment secrets in the
Runtime service.

The image is pinned to Python 3.12.14 by base-image digest and pip 25.0.1. Run
unit tests with `python -m pytest tests`; validate deployment wiring with
`docker compose config --quiet`. The end-to-end acceptance script
`python tests/docker_acceptance.py` requires the Compose stack to be running.
