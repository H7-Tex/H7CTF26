# Schrödinger Package

Astra Package Exchange is an internal Python package registry for uploaded
wheels, inspection results, file inventories, and runtime sessions. Inspector
and Runtime process the same uploaded wheel independently.

## Run locally

```sh
docker compose -f challenge/docker-compose.yml up --build
```

The portal listens on `http://localhost:8080`. Registry, Inspections, Runtime,
Policy, and API are independent views. Uploading a wheel stores it without
automatically starting inspection or Runtime. The JSON API is documented at
`/api-help`; endpoints are under `/api/` and `/api/v1/`. Only the portal
is published by Compose.

For local runs, Compose mounts `challenge/flag.txt` into the Portal only. Set
`FLAG` in the environment to override that dummy placeholder. Runtime receives
neither the flag value nor the flag file; the Portal releases it after the
intended Runtime result.

For local Python development, install `challenge/requirements.txt` and run
`python -m schrodinger.main portal` from `challenge/`. The other roles are
`inspector` and `runtime`.

## Tests

From `challenge/`, run `python -m pytest`. Compose configuration can be checked
with `docker compose -f docker-compose.yml config` from that directory.

The Inspector records the first occurrence of a repeated module path, while
Runtime verifies the last occurrence installed by pip. The reference package
generator is `solution/solve.py`.
