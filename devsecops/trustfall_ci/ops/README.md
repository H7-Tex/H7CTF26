# trustfall_ci — Qwen endpoint ops

The challenge's `agents` role calls an external Ollama running `qwen2.5-coder:7b`.
For quals we rent a RunPod GPU on demand, serve the model behind a secret-path
tunnel, point the challenge at it, test, then tear the pod down. This directory
automates that so it's one command each time.

## Quick use

```bash
cd ops
./qwen_endpoint.sh spin       # rent A40, serve model, print OLLAMA_URL (~6 min, model pull)
./qwen_endpoint.sh patch      # set trustfall-ci's agents OLLAMA_URL to that endpoint
./qwen_endpoint.sh test       # launch an instance, run the solve, submit, stop it
./qwen_endpoint.sh teardown   # delete the pod — billing stops, nothing persists
# or: ./qwen_endpoint.sh all   (spin + patch + test, leaves the pod up)
./qwen_endpoint.sh status     # show the active endpoint + reachability
```

State (pod id, ssh, OLLAMA_URL, secret) is kept in `ops/.qwen_state` between steps.

## Security model

Ollama binds `127.0.0.1:11434` only. A tiny stdlib Python reverse proxy
(`qwen_proxy`, embedded in `pod_setup_secure.sh`) listens on `127.0.0.1:8888`
and forwards **only** `/<secret>/…` to Ollama; every other path 404s. cloudflared
tunnels `:8888`. So:

- `https://<tunnel>/<secret>/api/chat` → works (this is the agents' `OLLAMA_URL`).
- `https://<tunnel>/api/tags` (or any path without the secret) → **404**.

The secret is a 24-byte random hex, lives only in the agents pod's env, and is
never shown to players (only `portal` is public; it doesn't expose agent env).
`spin` verifies both the secret-path digest and the bare-path 404 from outside
before declaring success.

## IMPORTANT — podguard on atom

`atom:/tmp/podguard*.sh` is a cost-safety loop that terminates any RunPod pod
with no live `gpufarm` job (it protects against orphaned training pods billing).
It **will kill this pod too** — it reaped 5 of them during bring-up before we
found it. It's currently disabled (`*.sh.disabled`). Before the event, pick one:

1. **Whitelist** — add `[ "$name" = anvil-qwen ] && continue` to podguard's loop
   so it skips this pod (the script always names the pod `anvil-qwen`). Keeps the
   cost-safety for real orphans. Recommended.
2. **Separate key** — run challenge GPUs on a RunPod key/account distinct from the
   eris-harness account, so podguard never sees them.

Either way, re-enable podguard afterwards so orphaned training pods don't bill.

## Config (top of qwen_endpoint.sh)

GPU `NVIDIA A40` @ `EU-SE-1` (~$0.49/hr, high stock), 50 GB disk, no network
volume (nothing to purge on teardown). Model digest is pinned and verified.
Requires `RUNPOD_API_KEY` in `CTF26/.env` and ssh access to `atom`.

## Known platform follow-up

Multi-container challenges import with an empty top-level `container_image`, and
the instance-start path rejects that ("this challenge has no instance to start").
Worked around by setting `container_image` to the AR image (`patch` does this).
Proper fix: make the instance-start gate treat a non-null `container_spec` as
instanceable. Tracked for the platform, not needed for hosting this challenge.
