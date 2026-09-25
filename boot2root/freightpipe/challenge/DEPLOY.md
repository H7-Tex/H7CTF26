# Freightpipe — Deployment notes (for Finals)

## Topology
One **sysbox pod** = the "factory host". Inside it, this `docker-compose.yml` runs the whole stack
(gitea, woodpecker-server, woodpecker-agent, registry, prod, reviewbot). Nested unprivileged Docker is
required because:
- the woodpecker-agent drives the inner Docker daemon to run CI step containers,
- `prod` drives it too (crane-pull → docker load → run the deployed app as a sibling),
- **stage 4** runs a *privileged* CI step that mounts the pod's `/` — that host is the pod itself
  (sysbox sandboxes it), so escaping to "factory-host root" stays inside the per-team pod.

Runtime: **runc + sysbox** (NOT gVisor — the stage-4 step needs `privileged`/allowPrivilegeEscalation,
which the GKE gVisor Warden webhook forbids). This is the same relaxed-runtime node pool sparrow_freight
and Sealed need. Per-team, disposable, **no egress** except player-inbound. Reset = destroy + respawn.

## Player-exposed ports (map these out of the pod)
- `WEB_PORT`  → gitea:3000   (web + git http)
- `SSH_PORT`  → gitea:22     (git ssh; optional)
- `WOODPECKER_PORT` → woodpecker-server:8000  (read-only build logs; the in-band output channel)
- `PROD_WEB_PORT`   → prod:9000  (the live app + its /deploy webhook)
Registry (5000) and the woodpecker gRPC (9000 internal) stay INTERNAL — do not expose.

## Split-horizon URLs (set these to the player-facing base)
- `GITEA_ROOT_URL`   = http://<player-host>:<WEB_PORT>/   (web links + shown clone URLs)
- `WOODPECKER_HOST`  = http://<player-host>:<WOODPECKER_PORT>
- `GITEA_PUBLIC_URL` = same as GITEA_ROOT_URL (drives the Woodpecker OAuth redirect)
The CI pipeline clones via the hardcoded in-network `http://gitea:3000/...`, so the agent never needs to
resolve the player-facing host — split-horizon safe.

## Per-team flags (injected at spawn)
Four flags, one per stage:
- `FLAG1`  — stage 0, lives in the `freightpipe-internal` repo (seeded by gitea/entrypoint.sh).
- `USER_FLAG` — stage 1, injected as the Woodpecker secret `user_flag` (reviewbot env).
- `FLAG3`  — stage 3, injected into the deployed prod container (prod env).
- `ROOT_FLAG` — stage 4, must be written to **`/root/root.txt` on the pod fs** by the pod entrypoint
  before the stack starts (the privileged step mounts `/` to read it). NOT yet wired in compose — the
  pod entrypoint should `echo "$ROOT_FLAG" > /root/root.txt` (see the local validation, which used a
  throwaway dir instead of `/`).
Per-team uniqueness: pass distinct values per instance. If Anvil injects a single `$FLAG`, derive the
four deterministically (e.g. HMAC(`$FLAG`, "user"|"prod"|"root"|"recon")) in the pod entrypoint and set
FLAG1/USER_FLAG/FLAG3/ROOT_FLAG + submit-side expected values accordingly. **Confirm the multi-flag
per-team model with the platform** (challenge.yml currently lists 4 flags; see its comments).

## No-egress: base-image mirroring (REQUIRED for the sealed pod)
Everything the stack + CI pulls must be present without internet:
- Stack images: gitea/gitea:1.22.6, woodpeckerci/woodpecker-server+agent:v3.18.1(-alpine),
  registry:2.8.3, python:3.12-alpine, freightpipe-prod (built from ./prod), woodpeckerci/plugin-kaniko,
  alpine/git:2.45.2. Pre-pull into the pod image.
- **kaniko base pull**: the publish step builds `FROM python:3.12-alpine`, which kaniko pulls from Docker
  Hub. In the sealed pod, mirror that base into the internal registry at build time and change scripts'
  Dockerfile to `FROM registry:5000/python:3.12-alpine` + add `insecure_pull: true` to the plugin
  settings. (Locally this "just works" because the dev host has egress.)

## Hardening TODO before go-live (M6 remainder)
- Registry currently has NO auth (insecure http). Add htpasswd for `REGISTRY_USER`/`REGISTRY_TOKEN` so
  the looted registry cred is real (the deploy gate is already the HMAC webhook, so this is realism, not
  a blocker).
- Audit the box for any OTHER privileged/SUID/sudo path — the ONLY intended root is the stage-4
  trusted-repo privileged step (validated: the stage-1 CI job is unprivileged + socket-free).
- `prod` creates a `prod-app-live` sibling container NOT managed by compose — the pod teardown must
  `docker rm -f prod-app-live` (irrelevant if the whole pod is destroyed).
