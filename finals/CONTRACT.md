# H7CTF'26 Finals: service author contract (v1.1)

Every finals service, checker, exploit and hill is built against this file. If something here is wrong or missing, ask Finals-3 before you work around it. Breaking changes bump the version at the top.

Event: Sat 24 Oct 12:00 to Sun 25 Oct 12:00 IST, on-site, 15 teams + 1 NOP team. Attack-Defense + King of the Hill, no AI tools for players.

---

## 1. What you deliver

```
finals/services/<slug>/
├── README.md        organizer only: every bug, its correct patch, the tempting wrong patch, and which checker step catches it
├── service/         exactly what a team gets in its repo: source, Dockerfiles, docker-compose.yml, vendored deps
├── checker/         enochecker3 checker: checker.py, requirements.txt (pinned), Dockerfile
├── exploits/        one standalone exploit per flag store, minimum (store0_<name>.py, store1_<name>.py)
├── patches/         store<N>_correct.patch and store<N>_wrong_<name>.patch for every known wrong patch
└── gate.yml         the patch matrix for the gate runner (section 8)
```

Start from `finals/_template/`. Hills live under `finals/hills/<slug>/` with the same shape, minus flag stores (section 10).

## 2. The box your service runs on

- One vulnbox per team: x86_64, 4 vCPU, 8 GB RAM, Ubuntu, Docker + compose. All six services share it.
- **No internet** inside the game network. An offline mirror serves apt, pip, npm, Go modules, crates and a docker pull-through cache. Your images must build and run with only that.
- Teams patch through a pipeline (model C). They push to their own git repo. **We** build the image from that commit, using your protected Dockerfile and taking only the files on your `patchable` allowlist from the team, and swap the container after our checker suite passes against a staging copy. Root-on-box (model A) is the fallback. Your service must work under both.
- **Only org-built images run on production.** A team can change the code under `patchable`, never the Dockerfile, the compose file, the base image or the dependency set. This is what stops a team from shipping a stripped-down clone that passes the checker.

### compose rules (enforced by the gate)

- One service = one compose project in `service/docker-compose.yml`. Extra containers (a database, a worker) are fine inside it.
- Every container sets `cpus:` (sum for your project at most `1.5`) and `mem_limit:` (sum at most `1g`).
- `restart: unless-stopped`. No `privileged`, no `cap_add`, no `network_mode: host`, no `pid: host`, no docker socket, no host bind mounts. Named volumes only.
- Listen on your assigned port (section 11). Ready within 20 s of `up`.
- Logs go to stdout and stderr.
- **Dockerfiles are protected, cache-friendly and offline.** Install dependencies first, then `COPY` the patchable source **last**, so a team patch rebuilds in under 60 s with a warm cache. Pin base images by digest. Vendor what the mirror can't serve. Build and run as an unprivileged user.
- **Declare the patchable allowlist** in `gate.yml` (`patchable:`, paths relative to `service/`). Keep it to the code a defender should fix: handlers, models, config files. Leave out the Dockerfile, the compose file, dependency manifests and vendored libraries, except the one service that carries the scheduled incident in `vendor/` (section 13), whose vendor path must be patchable. Every patch in your matrix must touch only allowlisted paths (the gate checks this).
- Keep the flag-bearing data for at least 15 min, and prune anything older than 30 min. The box must not grow without bound over 24 h.
- Secrets that differ per box (signing keys, admin passwords) are generated on first boot into a volume, never baked into the image. Two boxes must never share a secret (the gate checks this).

## 3. Flags

- Format: `H7CTF\{[A-Z2-7]{32}\}`. Exactly 39 bytes, ASCII. Size your fields for it.
- The checker hands you the flag. Store it verbatim and never derive anything from its content.
- Flags are valid for 5 ticks (10 min at a 120 s tick). The engine re-checks every still-valid flag each tick, so a service that loses older flags drops to RECOVERING.

## 4. Flag stores and attack info

- Each flag store is one **flag variant** of your checker (`@checker.putflag(0)`, `(1)`, ...). Two stores per service.
- `putflag` may return a string. That string is the store's **attack info** and is published to every team each tick at `/api/v1/arena/attack-info` (EnoEngine `attack.json` shape). Use it for what attackers legitimately need to aim, such as a username or an object id.
- Attack info is at most 200 bytes, preferably a JSON object (`{"user":"k3vin_19"}`). It must never contain the flag, a password, or anything that hands over the flag without the bug.

## 5. Checker

Python 3.12 with `enochecker3==0.14.0`. Start from `_template/checker/`.

- `Enochecker("<ServiceName>", <port>)`. The service name is also its MongoDB database name, and must be unique across the slate.
- MongoDB is provided by the runner through `MONGO_HOST`, `MONGO_PORT`, `MONGO_USER` and `MONGO_PASSWORD`. Use `ChainDB` (keyed by `taskChainId`) for anything getflag needs later.
- Implement, at minimum:
  - `putflag` and `getflag` for each store;
  - one `putnoise` and `getnoise`;
  - one `havoc` that exercises the risky feature legitimately;
  - one `exploit` per store, used only by the gate.
- **Never return INTERNAL_ERROR for something the team did.** Raise `MumbleException` when the service misbehaves and `OfflineException` when it's unreachable. INTERNAL_ERROR means our bug and is credited to the team.
- **MUMBLE messages name the feature, never the bug.** Write "export: embedded page content missing", not "SSRF filter blocked us". Players see these messages, so a wrong patch should teach without leaking.
- **Look like a normal user.**
  - Randomized realistic usernames and content, a realistic user-agent pool and realistic request order.
  - No fixed marker that a filter could key on.
  - Probe the dangerous feature with legitimate, exploit-shaped input, so blanket filters cost SLA.
- **Be fast and safe under load.** Async throughout, no global locks, no infinite retries. Budget: p95 under 5 s per task, hard cap at the task timeout (at most 30 s, the library keeps a 2 s buffer). 15 teams times about 20 tasks per tick land on your checker.
- Tolerate service restarts, ±120 s of clock skew, and repeated getflag calls for the same chain.

## 6. Exploits

- `exploits/store<N>_<name>.py`, standalone (stdlib, `requests`, `httpx` or `pwntools`). The usage line is `python3 store0_x.py <host> [attack-info-json]`, and it prints every flag it finds to stdout.
- Each store's exploit must also exist as a checker `@checker.exploit(N)` so the gate can run it the ENO way.

## 7. Bug design rules

- Each store has 2 intended paths, an easier one and a harder one. **Core bugs only** in the first build. Stretch bugs ship only after the gate passes with time to spare.
- Every bug sits inside a feature the checker uses every tick. Name the correct patch and at least one tempting wrong patch in README.md, and prove in `gate.yml` that the checker catches the wrong one.
- Banned:
  - RCE as an intended path;
  - destructive writes, meaning an attacker must never delete or corrupt other teams' data or checker state;
  - brute force;
  - victim-browser or headless-bot designs;
  - timing races;
  - endpoints that are expensive enough to DoS the box;
  - any LLM;
  - anything that needs the internet.
- No dated classes: no `strcpy` echo server, no guestbook SQLi, no `unserialize` toy.
- Write unintended-bug risk down in README.md. Native code gets a fuzz pass before the gate.

## 8. The gate (patch matrix): nothing ships without it

`finals/tools/gate.py <service-dir>` boots the service from `service/`, runs the real checker against it through the ENO protocol, and checks each of these:

1. **Clean service:** every putflag, getflag, putnoise, getnoise and havoc variant is OK for 3 consecutive rounds.
2. **Exploits work:** every exploit variant recovers its flag from the clean service.
3. **Correct patches:** for every `store<N>_correct.patch`, the checker stays OK and that store's exploits fail.
4. **Wrong patches are caught:** for every `store<N>_wrong_*.patch`, the checker reports MUMBLE or OFFLINE.
5. **Box isolation:** two fresh boots share no generated secret.
6. **Restart resilience:** restarting the service between rounds keeps old flags retrievable.
7. **Compose rules** from section 2.
8. **Patchable allowlist:** every patch in `gate.yml` touches only `patchable` paths.

`gate.yml` lists the patches and the expected outcome of each. Run the gate locally before review.

## 9. Review path

author self-gate -> Codex adversarial validation (the quals pipeline) -> Finals-3 review -> Finals-2 sign-off -> shipped into the vulnbox image. A service that fails the gate at the Fri 18:00 rehearsal ships later or not at all.

## 10. Hills (King of the Hill)

- Keep the quals control contract unchanged.
- `GET /koth/status` returns `{"holder": "<tag>"|null, "since": <unix>}`. It stays unauthenticated and un-rate-limited.
- `POST /koth/reset` takes a `Bearer KOTH_ADMIN_TOKEN` and restores clean state.
- Claims bind the team tag with `HMAC(rpc_secret, round || tag)`. The write-gate verifies at `KOTH_VERIFY_URL`.
- Doors and Locks: each round opens 4 of 8 doors (drawn by `HMAC(round, secret)`). The king may lock at most 2, and only doors it has walked through (it locks with the door token).
- Open the port before any slow startup work. Survive floods with per-IP limits before auth.

## 11. Ports

| Slot | Service | Port |
|---|---|---|
| S1 | Harbor ID | 7001 |
| S2 | TidePay | 7002 |
| S3 | Bollard | 7003 (raw TCP) |
| S4 | Berth Board | 7004 |
| S5 | Dockyard | 7005 |
| S6 | Tariff Studio | 7006 |
| spare | Pilot Line | 7007 (gRPC) |

Extra containers stay on the compose network and are not published.

## 12. Player-facing text

Team README, UI copy and error strings: no em or en dashes (use hyphens), short and plain. Names and descriptions go through the house-voice pass.

## 13. The scheduled incident (one service only)

One wave-1 service carries a readable backdoor in `vendor/`. It activates at exactly Sun 09:00 IST and never earlier. The gate tests the clock. No checker path may depend on it, so removing it correctly always passes the gate.
