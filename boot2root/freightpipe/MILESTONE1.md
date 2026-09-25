# Freightpipe — Milestone 1 (Gitea foundation + stage 0) — VALIDATED

Run: `cd challenge && docker compose up -d` (local test: `WEB_PORT=3300 SSH_PORT=2222 docker compose up -d`).
Deliverable ports default to 3000 (web) + 2222 (git-ssh).

## What's built
- `challenge/docker-compose.yml` — single `gitea` service (gitea/gitea:1.22.6), fresh `/data` (tmpfs) each
  run → seeds deterministically on boot; healthcheck gates on `.freightpipe-seeded` + `/api/healthz`.
- `challenge/gitea/entrypoint.sh` — seeds on first boot: admin, `dev` (repo owner), `contributor`
  (the low-priv leaked identity), three repos, a scoped PAT captured live, git-history token leak,
  branch protection, flag1.

## Stage-0 chain (all PASS)
1. `freightpipe-scripts` (PUBLIC) — anon-clone; `git log --all -p` recovers the leaked PAT
   (committed in `.env.deploy` then removed in a later commit; NOT in HEAD). **flag1 lives in the
   private `freightpipe-internal`, readable with the token** = H7CTF{fl4g1_l34k3d_t0k3n_in_g1t_h1st0ry}.
2. token WRITES `freightpipe-scripts` (contributor is a write-collaborator) — the I-PPE poison surface
   (`scripts/build.sh`, which the README says the prod-app pipeline executes).
3. token can NEITHER read NOR push `prod-app` (PRIVATE + contributor NOT a collaborator) — verified.

## KEY GITEA AUTHZ FINDINGS (critical for Milestone 2 — Woodpecker)
Discovered by testing; these shaped the design and MUST inform CI config:
- **Any authenticated user can push to a PUBLIC repo** in this Gitea (a fresh non-collaborator pushed
  new branches to a public repo). So "public + read-only" gives NO write protection.
- **Read-collaborators can push** too (not pull-only as expected).
- **Branch-protection `enable_push:false` did NOT block direct pushes** in testing (rule exists, push
  still succeeded).
- **PRIVATE + non-collaborator IS fully blocked** (can't even see the repo — 404). ← the reliable guard.
=> Per-repo write control here relies on **private + non-collaborator**, not on branch protection or
   read perms. prod-app is therefore private+non-collab; the player's only influence is the trusted
   `build.sh`. **M2 consequence:** the anti-cheese for the pipeline (which refs/PRs Woodpecker builds)
   MUST be enforced at the Woodpecker layer — only build prod-app's protected main + review-bot-approved
   PRs, run PRs with the base config, never build arbitrary player-pushable refs. Do NOT rely on Gitea
   push perms to stop D-PPE.

## Next: M2 = Woodpecker (server+agent, Gitea OAuth) + wire prod-app's pipeline to run the trusted
`build.sh`; validate the I-PPE (poison build.sh → pipeline runs it → RCE in the CI job → user.txt),
with the CI job unprivileged + socket-free.
