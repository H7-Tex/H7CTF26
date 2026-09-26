# ZOMBIE WORKER

Relay is a field-operations PWA built for technicians working through unreliable connections. Its releases support offline drafts, background sync, and a service-worker-managed application shell. The player's own browser establishes the old worker before the routine release transition; there is no private bot completing the stale-worker flow. The runnable challenge is in `challenge/`.

Run locally with Docker Compose:

```sh
docker compose -f challenge/docker-compose.yml up --build
```

Open `http://localhost:8080`. The local runner supplies dummy flag values. Use the normal Sync now action to advance a session from v1 to v2 while its existing worker client remains open. Production should use HTTPS and inject the platform `FLAG` and internal service credentials through the challenge runtime.

Automated checks live in `challenge/tests/`. See `challenge/README.md` for browser-test setup and `solution/README.md` for the author solve.
