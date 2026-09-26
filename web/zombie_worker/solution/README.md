# Reference solve

Run against a fresh instance through HTTPS:

```sh
python solution/solve_phase2.py --url https://<instance-host>
```

The solver uses a clean Chromium profile. It first observes and controls the actual v1 worker, reads the historical package metadata, and saves a valid pre-rollout preference through the v1 UI. Sync now advances that session. It then confirms that the real v2 page/API coexist with legacy active/controller and current waiting, saves a normal v2 scope, waits for that preference revision to be snapshotted, stages the intercepted plan, and explicitly flushes the worker outbox via MessageChannel. The final flag arrives through the normal report archive.

The script aborts if v1 was not controlling before rollout, if waiting/current does not coexist with the legacy controller, if the browser key is missing or extractable, if staging did not produce a pending outbox action, or if publication/export fails. It does not write a legacy preference after rollout, construct a replay envelope, or provide a browser state shortcut.

For local verification:

```sh
python challenge/tests/acceptance_https_ingress.py --local-tls
python challenge/tests/acceptance_https_ingress.py --url https://<fresh-anvil-instance>
```

The TLS ingress test verifies one origin, forwarded Host/scheme, Secure HttpOnly session cookie, real worker registration, outbox staging, replay, and export. A local TLS pass does not establish that a live Anvil instance was tested.
