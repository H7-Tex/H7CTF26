# Engine runbook — H7CTF'26 finals

Node of record: OCI `ap-hyderabad-1`, accessible via `atom ~/bin/oci-sahalmn`.
Event: finals.h7tex.com | 2026-10-24 14:00 IST to 2026-10-25 14:00 IST (24h).

## Quick references

| thing | where |
|---|---|
| gameserver process | `systemctl status anvil-gameserver` on the game node |
| API replicas | GKE `anvil` namespace, deployment `anvil-api` (2 replicas) |
| checker fleet | `docker compose -f /srv/checkers/docker-compose.yml` on the checker node |
| DB | Postgres on the game node (connect string in `~/.secrets/anvil.env`) |
| internal token | `ANVIL_GAME_INTERNAL_TOKEN` in `~/.secrets/anvil.env` |

Metrics endpoint (require internal token):

```
curl -s -H "Authorization: Bearer $ANVIL_GAME_INTERNAL_TOKEN" \
  http://gameserver:8080/api/v1/internal/arena/metrics | jq .
```

Gate endpoint (dry-run a service deploy):

```
curl -s -X POST -H "Authorization: Bearer $ANVIL_GAME_INTERNAL_TOKEN" \
  -d '{"service":"<slug>","address":"<staging-ip>","rounds":1,"timeout_s":30}' \
  http://gameserver:8080/api/v1/internal/arena/gate | jq .
```

## Deployment split

| component | controller | config key |
|---|---|---|
| Gameserver | yes | `game.controller_enabled=true` |
| API replica | no | `game.controller_enabled=false` |

The gameserver is the single process that runs the tick loop, checker dispatch, KotH polling, and the gate API. API replicas are stateless and serve HTTP only. If the gameserver restarts, the in-flight tick resumes from the last committed tick (idempotent — already-closed ticks are skipped).

## Checker fleet sizing

Run 3x the minimum needed for peak-tick load:

- Peak load = `n_teams * n_services * (flag_stores + noise_variants + havoc_variants)` tasks per tick.
- At 16 teams * 6 services * 3 variants = 288 tasks / tick, with a 2-minute tick, each checker needs to handle ~48 req/min. One container handles 5-10 concurrent requests comfortably.
- **Minimum**: `ceil(tasks_per_tick / (concurrency * tick_interval_seconds))` containers per service.
- **Target**: 3x minimum. With 6 services at 1 container each, run 3 containers per service (18 total) plus 1 MongoDB.

Regenerate the compose file after adding services:

```bash
cd /home/abu/Main/Projects/H7CTF26
./finals/infra/checkers/gen-compose.sh \
  --services-dir ./finals/services \
  --out /srv/checkers/docker-compose.yml \
  --mongo-host 10.60.201.20

# load checker_refs into DB
PGPASSWORD=... ./finals/infra/checkers/import-checker-refs.sh \
  /srv/checkers/checker-refs.env
```

## First 60 minutes: fault response

**Tick not advancing (lag_s keeps growing):**

1. Check `metrics` — is `tick.status` still `running` and `open_for_s > 3 * interval_s`?
2. Check gameserver logs: `journalctl -u anvil-gameserver -n 100 --no-pager`.
3. If a DB connection error, verify `pg_isready -h <host>` and restart Postgres if needed.
4. Restart the gameserver: `systemctl restart anvil-gameserver`. It will re-run the current tick if it was still open (idempotent).
5. If the tick was closed but standings did not update, run `curl -X POST /api/v1/admin/game/recompute-standings` (admin token).

**Checker DOWN rate > 20% for one service:**

1. Check `metrics` — which service, what error_rate?
2. Check the checker container: `docker compose -f /srv/checkers/docker-compose.yml logs checker-<slug> --tail=50`.
3. If the checker is OOM (exit 137), increase memory limit in the compose file and restart.
4. If the service itself is down (not the checker), first confirm with `nc -z <team_ip> <port>`. If the service is genuinely down, the DOWN SLA is correct — no action needed.
5. If the checker is crashing on a bug, roll back: `docker compose pull checker-<slug> && docker compose up -d checker-<slug>`.

**Checker fleet MongoDB unreachable:**

1. Check `docker inspect anvil-p2-mongo` health status.
2. Restart: `docker compose restart mongo`. Checkers will reconnect automatically (they have `depends_on: mongo: condition: service_healthy`).
3. Checker tasks during the restart window will fail with ERROR (organiser fault). Do not manually adjust SLA — Finals-3 handles ORG_FAULT credit.

**Gate API returning 404 for all calls:**

- `game.internal_token` is empty. Set `ANVIL_GAME_INTERNAL_TOKEN` in the gameserver's env and restart.

**Gate API returning errors for a specific service:**

- Verify the service row in `game_services`: `SELECT slug, checker_ref, port FROM game_services;`
- If `checker_ref` is null, run `import-checker-refs.sh` to populate it.

## SNAT check (placeholder — coordinate with P4-Infra)

The checker fleet dials team VMs via the game router (SNAT). Verify SNAT is working before the event:

```bash
# check_snat.sh — placeholder; P4-Infra implements the full version
# Expected: each team IP reachable from the checker node on the service port.
for team_ip in $(psql ... -c "SELECT vulnbox_ip FROM game_teams" -t -A); do
  nc -z -w 2 "$team_ip" 8080 && echo "OK $team_ip" || echo "FAIL $team_ip"
done
```

P4-Infra owns the full NAT topology; run their `check_snat.sh` from the checker node before t0.

## End-of-event

1. At `t0 + 24h`: pause game via `game.state = "paused"` (platform_settings).
2. Wait for the current tick to close (check `metrics` — `tick.status = "closed"`).
3. Run final standings recompute: admin API.
4. Stop the outbreak bot if it is running (`game.outbreak.enabled = false` + gameserver restart).
5. Stop checker fleet: `docker compose -f /srv/checkers/docker-compose.yml down`.
6. Set `game.state = "stopped"`.
7. Export final scoreboard: `GET /api/v1/scoreboard` (public).

## Config keys (all in `config.yaml` or env)

| key | env | default | purpose |
|---|---|---|---|
| `game.enabled` | `ANVIL_GAME_ENABLED` | false | enables the engine at all |
| `game.controller_enabled` | `ANVIL_GAME_CONTROLLER_ENABLED` | true | runs the tick loop (false = API replica) |
| `game.internal_token` | `ANVIL_GAME_INTERNAL_TOKEN` | "" | enables internal endpoints (gate, metrics, deploys) |
| `game.outbreak.enabled` | `ANVIL_GAME_OUTBREAK_ENABLED` | false | runs the wave bot |
| `game.tick_interval` | `ANVIL_GAME_TICK_INTERVAL` | 2m | tick cadence |
| `game.checker.task_timeout` | `ANVIL_GAME_CHECKER_TASK_TIMEOUT` | 30s | per-checker-call timeout |
| `game.checker.concurrency` | `ANVIL_GAME_CHECKER_CONCURRENCY` | 8 | per-service in-flight checker calls |
