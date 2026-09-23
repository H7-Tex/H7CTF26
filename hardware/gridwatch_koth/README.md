# GridWatch Operator Console (King of the Hill)

`hardware` / `hard` / single SHARED static instance, KotH (hold-time scored, no flag).

The first true competitive King-of-the-Hill target for H7CTF'26 quals. GridWatch is a web
SCADA operator console for a substation feeder; only one operator can hold the seat.
Teams exploit the console to install their own team token as the active operator, and
score for as long as they hold the seat. The seat can be stolen by another team at any
time and is auto-reset periodically, so the field keeps fighting over it.

This is the throne half of the KotH system. The engine half (shared-arena wiring, per-team
KotH token issuance, the hold-time scorer that polls `/koth/status`, scoreboard
integration, VPN attribution, watchdog) is owned by the platform (CTF26-Finals). The
contract between them is `GET /koth/status`.

## The contract (throne <-> engine)
- `GET /koth/status` -> `{"holder": "<team-token>", "since": <unix>}` (holder null if the
  seat is unheld). The engine polls this every ~15s and accrues hold-time to the team the
  token maps to. The throne never calls the engine.
- The team token is an opaque string; the throne stores whatever the winner installs as
  `holder` verbatim and echoes it. The engine maps token -> team (it owns the token table).
- `/koth/status` is never rate-limited (the poller must always read it).

## The vulnerability (what teams exploit)
The console issues RS256 sessions and exposes its verification public key at
`GET /api/operator/pubkey`. The token verifier trusts the JWT header `alg` and, for
`HS256`, uses the PEM of that public key as the HMAC secret: the classic RS256 -> HS256
key-confusion. An attacker forges an `HS256` token with `role: admin` signed with the
public key, then `POST /api/operator/claim {"holder_token": "<your team token>"}` to seize
the seat. Normal logins only grant a `viewer` session, which cannot claim.

Hard to discover once, trivial to script to re-take = ideal KotH churn.

## Anti-grief (baked into the throne)
- **Self-heal:** the seat resets to unheld every `KOTH_RESET` seconds (default 90), so no
  team can hold it forever and nothing stays stuck. Losing the seat on reset is expected;
  re-take it.
- **Non-destructive win:** claiming only sets the holder token; there is no endpoint that
  can brick the service or block the reset.
- **Rate limits:** the exploit surface (`/api/login`, `/api/operator/pubkey`,
  `/api/operator/claim`) is rate-limited per source IP, and `/api/operator/claim` has a
  per-team-token cooldown so no team can spam-dominate. `/koth/status` is exempt.

## Files
- `challenge.yml` : PROVISIONAL KotH definition (scoring: koth, instancing: static, no
  flag). Final schema/field names come from the engine (CTF26-Finals); this is a placeholder.
- `challenge/app.py` : the throne (Flask; JWT confusion vuln, claim, `/koth/status`, self-heal, rate limits).
- `challenge/Dockerfile` : the image (`h7ctf26/gridwatch-koth`); single gunicorn worker so
  the in-memory seat state stays consistent for the shared instance.
- `solution/exploit.py` : reference exploit (fetch pubkey, forge HS256 admin, claim the seat).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
KOTH_RESET=5 python3 challenge/app.py                 # dev server on :8080
python3 solution/exploit.py http://127.0.0.1:8080 TEAM-A-TOKEN
```
Verified end to end: the exploit seizes the seat; a second team steals it; a `viewer`
session and a tokenless request cannot claim (403); the per-team cooldown returns 429;
`/koth/status` is never throttled; the seat self-heals to unheld on the timer.

## Status
Throne built + locally validated. Awaiting the engine's final `challenge.yml` schema and
the shared-arena wiring for joint end-to-end (2-3 team accounts really competing:
seize -> hold -> get knocked off -> retake, hold-time accrues, self-heal fires, scoreboard
moves). Do NOT publish until that joint e2e passes.
