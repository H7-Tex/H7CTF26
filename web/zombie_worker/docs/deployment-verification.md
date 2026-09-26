# Deployment verification record

## Scope

The local Compose and local TLS checks validate the two containers and the player's browser lifecycle on this repository revision. They do not establish the Anvil player path. Production verification requires two separately created on-demand instances with their own HTTPS origins and the published immutable image digests.

## Run once per fresh instance

After the candidate images are available to Anvil, create a new instance twice. From the repository root, run each command independently with its own evidence filename:

```sh
python challenge/tests/acceptance_https_ingress.py --url https://<instance-1-origin> --evidence https-instance-1.json
python challenge/tests/acceptance_https_ingress.py --url https://<instance-2-origin> --evidence https-instance-2.json
```

The HTTPS acceptance uses normal certificate validation and the Chromium reference solve. It checks a same-origin run, Secure HttpOnly session cookie, a player-created v1 controller surviving the v2 release, current waiting registration, outbox staging and signed replay, report packaging, and the final artifact. Keep the two origins distinct and record that each was created independently. Evidence output is redacted and must not contain the runtime flag.

Record the source commit and both resulting image digests in a copy of [anvil-ingress-evidence.template.json](anvil-ingress-evidence.template.json). Do not fill success fields until both runs pass. Keep that evidence with the tagged release or as a CI release artifact.

## Current status

- Local pytest, Chromium lifecycle, Compose, and local TLS-ingress acceptance: passed on the uncommitted source tree; see `local-acceptance-evidence.json`.
- Anvil production instances: not run; no per-instance origins have been supplied in this task.
- Release image publication and registry digests: not run.

Do not mark the challenge production-deployment verified or create the final release tag until the two Anvil runs and exact-commit CI/image provenance are recorded.
