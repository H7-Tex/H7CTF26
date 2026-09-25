# Milestone 2: Woodpecker CI

## Added

- `woodpecker-server` and `woodpecker-agent`, pinned to Woodpecker `v3.18.1`.
  The server uses the Alpine image because its bootstrap needs `/bin/sh`; the
  agent uses the standard image and Docker backend.
- Named volumes for the OAuth handoff, Woodpecker's SQLite state, and the
  agent registration state.
- A named `freightpipe-ci` Docker network. The agent tells the Docker backend
  to attach workflow containers to this network, allowing the seeded
  `http://gitea:3000/...` clone in `prod-app/.woodpecker.yml` to resolve.
- `prod-app/.woodpecker.yml` now sets `skip_clone: true`. Gitea 1.22 advertises
  its player-facing `localhost` clone URL, which is not valid from inside a
  workflow container. The workflow does not need an implicit checkout: its
  explicit prepare step clones the public shared scripts repo, and the build
  helper intentionally treats `app/main.py` as optional.
- `/var/run/docker.sock` is mounted only into the agent. It is not mounted into
  workflow containers by this milestone.
- `woodpecker/verify.sh`, which prints PASS/FAIL for server reachability, the
  OAuth handoff, agent registration, and server-to-Gitea connectivity.

## OAuth bootstrap

Gitea remains responsible for all deterministic seed state. After the existing
users, repositories, commits, collaborator permissions, leaked PAT, and branch
protections are created, `gitea/entrypoint.sh` does the following:

1. It sends an authenticated `POST /api/v1/user/applications/oauth2` as
   `freightadmin`.
2. The application is named `Woodpecker CI` and receives exactly
   `${WOODPECKER_HOST%/}/authorize` as its redirect URI.
3. The returned `client_id` and `client_secret` are validated and atomically
   written as `WOODPECKER_GITEA_CLIENT` and `WOODPECKER_GITEA_SECRET` in
   `/oauth/woodpecker.env` on the shared `woodpecker-oauth` volume.
4. The file is mode `0400`, owned by UID/GID `1000`, so the rootless
   Woodpecker server can read it. No credential value is written to logs.
5. `woodpecker/server-entrypoint.sh` waits for the file, exports it, validates
   both variables, and then execs `/bin/woodpecker-server`.

A fresh Gitea database removes any stale OAuth handoff before creating a new
application. If the Gitea data is already seeded but the handoff file is
missing, the entrypoint recreates the application and file.

## Woodpecker configuration

- Public host: `WOODPECKER_HOST`, default `http://localhost:8000`
- Published UI port: `WOODPECKER_PORT`, default `8000`
- Gitea API URL: `http://gitea:3000`
- Public Gitea OAuth host: `GITEA_PUBLIC_URL`, default
  `http://localhost:3000`
- Internal webhook callback: `http://woodpecker-server:8000`
- Open registration: enabled
- Admin on first OAuth login: `freightadmin`
- Agent endpoint: `woodpecker-server:9000`
- Agent backend: Docker
- Shared agent and gRPC secrets: deterministic defaults, both independently
  overridable with environment variables

Gitea permits external, loopback, and Docker-private webhook targets. The
separate internal webhook callback prevents a public `localhost` Woodpecker
URL from making Gitea call its own loopback interface.

When changing local ports, keep the advertised public URLs in sync. Example:

```sh
WEB_PORT=13000 \
SSH_PORT=12222 \
WOODPECKER_PORT=18000 \
GITEA_PUBLIC_URL=http://localhost:13000 \
WOODPECKER_HOST=http://localhost:18000 \
docker compose up -d
```

## Verification results (2026-09-25)

Static checks completed successfully:

- PASS: `sh -n` accepts all Gitea/Woodpecker entrypoint and verification
  scripts.
- PASS: `docker compose config --quiet` accepts the default and remapped-port
  configurations.
- PASS: Compose resolves matching server/agent secrets, matching public OAuth
  URLs, the internal webhook URL, and the shared `freightpipe-ci` network.
- PASS: the pinned `v3.18.1` and `v3.18.1-alpine` image tags are published by
  Woodpecker.

The required live command was attempted on remapped ports, but this build
session cannot connect to `/var/run/docker.sock`; Compose failed before it
could create any container, network, or volume:

```text
permission denied while trying to connect to the docker API at unix:///var/run/docker.sock
```

Consequently, `WOODPECKER_PORT=18000 ./woodpecker/verify.sh` reported:

```text
FAIL: woodpecker-server is not reachable at http://127.0.0.1:18000
FAIL: woodpecker-server cannot read the Gitea OAuth credentials
FAIL: woodpecker-agent logs do not show a successful registration
FAIL: woodpecker-server cannot reach Gitea
```

These are environment-blocked live checks, not observed service failures: the
stack never started. The requested `docker compose down -v` was also issued
and hit the same socket denial; there were no resources from the failed
bring-up to remove.

## Remaining pipeline enablement gap

On a Docker-capable host, first rerun the clean bring-up and
`./woodpecker/verify.sh`. Then sign in to Woodpecker once as `freightadmin`
through Gitea OAuth and activate `dev/prod-app`. Activation creates the Gitea
webhook. A later manual build or the not-yet-implemented review bot can then
trigger the already-seeded `.woodpecker.yml`, which clones
`dev/freightpipe-scripts` and runs `sh ./scripts/build.sh`.

No exploit, pipeline poisoning, or review-bot work is included here.
