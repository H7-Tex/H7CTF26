# Contributing — H7CTF'26 challenge standard

The bar: every challenge teaches a real technique, ships a working reference solve and a writeup, and deploys cleanly on Anvil. No guess-the-flag. Flag format: `H7CTF{...}`.

## Per-challenge directory

```
<category>/<name>/
├── challenge.yml
├── README.md
├── challenge/     source, Dockerfile, and the real flag
├── handout/       exactly what players download (no real flag)
├── solution/      solve.py + how-to-run
└── writeup/       README.md (intended path) + img/
```

`<name>` is kebab-case. Multi-service challenges nest per-service dirs under `challenge/` with a `docker-compose.yml`.

## `challenge.yml`

```yaml
name: string                 # required
author: string | [string]   # required
category: string             # required — matches the parent dir
difficulty: easy | medium | hard | insane   # required
description: string          # required, markdown; gated behind launch when the economy is on
sub_description: string      # optional, short pre-launch blurb (non-spoilery)
points: int                  # required — base points
flag: "H7CTF{...}"           # inline static flag, OR:
flags:
  - type: static | dynamic
    value: "H7CTF{...}"       # static only
    dynamic_flag_prefix: "H7CTF{"   # dynamic only; per-instance flag reaches the container as $FLAG
provide:                      # files given to players; the real flag must never appear here
  - path: handout/chall.zip
deploy:                       # omit for static-download challenges
  resource_type: docker | vm
  instancing: static | on_demand   # on_demand = per-team instance; static = external/no-instancer
  image: h7ctf26/<name>
  cpu_limit: "1.0"
  memory_limit: 512Mi
  exposed_ports: [{ port: 1337, protocol: tcp }]   # protocol: tcp | http
  instance_timeout: 1800     # on_demand
  max_extensions: 2
  ova: challenge/box.ova     # vm only
```

Anvil notes: `is_regex` and `network_mode` are unsupported (exact-match flags only); dynamic per-instance flags cover the unique-flag need. Full contract: `../h7ctf26-challenge-schema.md`.

## Flag / secrets rule

- The real flag lives only in `challenge/flag.txt` (or is injected per-instance via `$FLAG`) and is never in `handout/` or `provide:`. If a handout needs a flag file, ship a dummy `H7CTF{dummy}`.
- No infra secrets (tokens, deploy creds) in the repo.

## Ship checklist

- [ ] `challenge.yml` valid; all required fields.
- [ ] `README.md` card complete.
- [ ] Builds clean locally (`docker compose up`).
- [ ] Hosted service hardened: non-root, resource limits, jail where it takes untrusted input.
- [ ] `solution/solve.py` recovers the flag on a fresh instance.
- [ ] `writeup/README.md` explains the intended path; screenshots in `writeup/img/`.
- [ ] No real flag in the handout.
- [ ] Difficulty + flag format correct.

## Conventions

- Commits: `vX.X.X` subject (bump the last digit for most work), body is lowercase `- pointer` bullets. No AI trailer.
- Code: laziest thing that works (ponytail). **No comments** — rare exceptions lowercase.
