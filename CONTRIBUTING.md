# contributing: the h7ctf'26 challenge standard

the bar: every challenge teaches a real technique, ships a working reference solve + a writeup, and deploys clean on anvil. no guess-the-flag. flag format `H7CTF{...}`.

#### per-challenge directory

```
<category>/<name>/
├── challenge.yml
├── README.md
├── challenge/     source, dockerfile, and the real flag
├── handout/       exactly what players download (no real flag)
├── solution/      solve + how-to-run
└── writeup/       README.md (intended path) + img/
```

`<name>` is lowercase_underscores. multi-service challenges nest per-service dirs under `challenge/` with a `docker-compose.yml`. download-only challenges skip `handout/` and just `provide:` straight from `challenge/`.

#### challenge.yml

```yaml
name: string                 # required
author: string | [string]   # required
category: string             # required, matches the parent dir
difficulty: easy | medium | hard | insane   # required
description: string          # required, markdown; gated behind launch when the economy is on
sub_description: string      # optional, short pre-launch blurb (non-spoilery)
points: int                  # required, base points
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

**multi-container (compose-style) challenges** are supported: add a `deploy.services:` list and each role becomes its own pod on a private per-instance network, resolvable by name (`http://scanner:8081`). only roles with `public: true` get a route; the rest are internal. per-instance values `${INSTANCE_ID}`, `${INTERNAL_TOKEN}`, `${FLAG}` are substituted into a role's `env` — so `${FLAG}` reaches ONLY the role that declares it (never a player-facing one). `egress: true` opts a role into outbound internet (e.g. a shared LLM). omit `services:` and it's a plain single-image challenge, exactly as before.

```yaml
deploy:
  resource_type: docker
  instancing: on_demand
  image: h7ctf26/<name>          # shared by all roles unless a role sets its own image
  cpu_limit: "1.0"
  memory_limit: 512Mi
  instance_timeout: 1800
  services:
    - name: web                  # pod + service name (compose DNS)
      command: ["web"]           # -> container args (keeps the image ENTRYPOINT)
      public: true               # only this role is routed to players
      ports: [{ port: 8080, protocol: http }]
      env: { INSTANCE_ID: "${INSTANCE_ID}", BACKEND_URL: "http://backend:9000" }
    - name: backend              # internal only (no public)
      command: ["backend"]
      ports: [{ port: 9000, protocol: http }]
      env: { INTERNAL_TOKEN: "${INTERNAL_TOKEN}", FLAG: "${FLAG}" }   # FLAG scoped to this role only
    - name: worker
      command: ["worker"]
      egress: true               # outbound internet (blocked by default)
      env: { LLM_URL: "https://shared-llm.example" }
```

anvil notes: `is_regex` and `network_mode` aren't supported (exact-match flags only); dynamic per-instance flags cover the unique-flag need. full contract: `../h7ctf26-challenge-schema.md`.

#### flag / secrets rule
- the real flag lives only in `challenge/flag.txt` (or gets injected per-instance via `$FLAG`) and never appears in `handout/` or `provide:`. if a handout needs a flag file, ship a dummy `H7CTF{dummy}`.
- no infra secrets (tokens, deploy creds) in the repo.

#### ship checklist
- [ ] `challenge.yml` valid; all required fields.
- [ ] `README.md` card complete.
- [ ] builds clean locally (`docker compose up`).
- [ ] hosted service hardened: non-root, resource limits, jail where it takes untrusted input.
- [ ] `solution/` recovers the flag on a fresh instance.
- [ ] `writeup/README.md` explains the intended path; screenshots in `writeup/img/`.
- [ ] no real flag in the handout.
- [ ] difficulty + flag format correct.

#### conventions
- commits: `vX.X.X` subject (bump the last digit for most work), body is lowercase `- pointer` bullets. no ai trailer.
- code: laziest thing that works (ponytail). no comments.
