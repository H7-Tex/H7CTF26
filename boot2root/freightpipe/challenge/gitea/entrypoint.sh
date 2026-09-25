#!/bin/sh
# Freightpipe Gitea seed. Runs on every boot (fresh /data). Seeds the stage-0 recon foothold:
# a low-priv 'contributor' whose leaked PAT can WRITE freightpipe-scripts (the trusted build repo)
# but only READ prod-app (branch-protected) -> forces the I-PPE path, no direct D-PPE cheese.
set -eu

readonly GITEA_CONFIG=/data/gitea/conf/app.ini
readonly ADMIN_USER=freightadmin
readonly ADMIN_PASSWORD='FreightAdmin-2026!'
readonly DEV_USER=dev                       # owns the repos (the ops engineer)
readonly DEV_PASSWORD='FreightDev-2026!'
readonly CONTRIB_USER=contributor           # the low-priv identity whose token leaked
readonly CONTRIB_PASSWORD='Contributor-2026!'
readonly FLAG1='H7CTF{fl4g1_l34k3d_t0k3n_in_g1t_h1st0ry}'
readonly API=http://127.0.0.1:3000/api/v1
readonly OAUTH_ENV=/oauth/woodpecker.env
readonly WOODPECKER_HOST="${WOODPECKER_HOST:-http://localhost:8000}"

gitea_pid=''
seed_dir=''
cleanup() {
  [ -n "$seed_dir" ] && [ -d "$seed_dir" ] && rm -rf "$seed_dir"
  if [ -n "$gitea_pid" ] && kill -0 "$gitea_pid" 2>/dev/null; then
    kill "$gitea_pid" 2>/dev/null || true; wait "$gitea_pid" 2>/dev/null || true
  fi
}
trap cleanup INT TERM EXIT
log() { printf '[freightpipe-seed] %s\n' "$*"; }
as_git() { su-exec git:git gitea --config "$GITEA_CONFIG" "$@"; }

# API helpers authenticated as dev (repo owner)
api_post() { curl --fail-with-body -sS -u "$DEV_USER:$DEV_PASSWORD" -H 'Content-Type: application/json' --data "$2" "$API$1" >/dev/null; }
api_put()  { curl --fail-with-body -sS -u "$DEV_USER:$DEV_PASSWORD" -H 'Content-Type: application/json' -X PUT --data "$2" "$API$1" >/dev/null; }

bootstrap_woodpecker_oauth() {
  oauth_redirect="${WOODPECKER_HOST%/}/authorize"
  case "$oauth_redirect" in
    http://*|https://*) ;;
    *) log "invalid WOODPECKER_HOST: $WOODPECKER_HOST"; return 1 ;;
  esac
  case "$oauth_redirect" in
    *\"*|*\\*) log 'WOODPECKER_HOST must not contain quotes or backslashes'; return 1 ;;
  esac

  log "creating Woodpecker OAuth2 application (redirect: $oauth_redirect)"
  oauth_response=$(curl --fail-with-body -sS -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -H 'Content-Type: application/json' \
    --data "{\"name\":\"Woodpecker CI\",\"confidential_client\":true,\"redirect_uris\":[\"$oauth_redirect\"]}" \
    "$API/user/applications/oauth2")
  oauth_client=$(printf '%s\n' "$oauth_response" | sed -n 's/.*"client_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  oauth_secret=$(printf '%s\n' "$oauth_response" | sed -n 's/.*"client_secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  [ -n "$oauth_client" ] && [ -n "$oauth_secret" ] || {
    log 'Gitea OAuth2 response did not contain a client id and secret'
    return 1
  }
  case "$oauth_client$oauth_secret" in
    *[!A-Za-z0-9._-]*) log 'Gitea returned shell-unsafe OAuth2 credentials'; return 1 ;;
  esac

  oauth_tmp="$OAUTH_ENV.tmp.$$"
  umask 077
  printf 'WOODPECKER_GITEA_CLIENT=%s\nWOODPECKER_GITEA_SECRET=%s\n' \
    "$oauth_client" "$oauth_secret" > "$oauth_tmp"
  chown 1000:1000 "$oauth_tmp"
  chmod 0400 "$oauth_tmp"
  mv -f "$oauth_tmp" "$OAUTH_ENV"
  log 'Woodpecker OAuth2 bootstrap file ready'
}

git_commit() {
  GIT_AUTHOR_DATE="$2" GIT_COMMITTER_DATE="$2" \
    git -c user.name='Sparrow Freight Dev' -c user.email='dev@sparrow-freight.local' commit -q -m "$1"
}
# Repos are created with auto_init=true so Gitea builds the initial main commit itself:
# that clears the DB is_empty flag and registers the branch, which a bare
# "create empty + git init + push" does NOT (is_empty stays true -> the branches API
# returns null -> Woodpecker's manual "fetch branch head" 404s). We clone that seeded
# repo and layer our content on top, fast-forward.
clone_repo() {
  git clone -q "http://$DEV_USER:$DEV_PASSWORD@127.0.0.1:3000/$DEV_USER/$1.git" "$seed_dir/$1"
  cd "$seed_dir/$1"
}
push_repo() {
  git push -q origin main
}

log 'starting Gitea'
/usr/bin/entrypoint "$@" &
gitea_pid=$!

attempt=0
until curl -fsS http://127.0.0.1:3000/api/healthz >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  kill -0 "$gitea_pid" 2>/dev/null || { log 'gitea exited early'; wait "$gitea_pid"; exit 1; }
  [ "$attempt" -ge 120 ] && { log 'timeout waiting for gitea'; exit 1; }
  sleep 1
done

if [ -f /data/.freightpipe-seeded ]; then
  if [ ! -s "$OAUTH_ENV" ]; then
    bootstrap_woodpecker_oauth
  fi
  log 'already seeded'; trap - INT TERM EXIT; wait "$gitea_pid"; exit $?
fi

# A named OAuth volume can outlive Gitea's tmpfs data. Never let a fresh Gitea
# instance advertise stale client credentials from an earlier database.
rm -f "$OAUTH_ENV"

log 'creating users'
as_git admin user create --username "$ADMIN_USER" --password "$ADMIN_PASSWORD" --email 'admin@sparrow-freight.local' --admin --must-change-password=false >/dev/null
as_git admin user create --username "$DEV_USER" --password "$DEV_PASSWORD" --email 'dev@sparrow-freight.local' --must-change-password=false >/dev/null
as_git admin user create --username "$CONTRIB_USER" --password "$CONTRIB_PASSWORD" --email 'contributor@sparrow-freight.local' --must-change-password=false >/dev/null

log 'creating repositories (owned by dev)'
# prod-app is PRIVATE and contributor is NOT a collaborator -> the player can neither read nor push
# it (private + non-collaborator is fully blocked in Gitea; verified). The player's ONLY influence on
# prod-app's build is via the shared build.sh in freightpipe-scripts (public, contributor-WRITE) that
# prod-app's pipeline trusts = the I-PPE surface. internal is private + contributor read (flag1).
# (NOTE: Gitea lets any authed user push to PUBLIC repos and read-collaborators push too, so per-repo
#  write control here relies on private+non-collaborator, NOT on branch protection or read-perms.)
api_post '/user/repos' '{"name":"freightpipe-scripts","description":"Shared Freightpipe build helpers","private":false,"auto_init":true,"default_branch":"main"}'
api_post '/user/repos' '{"name":"prod-app","description":"Sparrow Freight production application","private":true,"auto_init":true,"default_branch":"main"}'
api_post '/user/repos' '{"name":"freightpipe-internal","description":"Private Freightpipe operations data","private":true,"auto_init":true,"default_branch":"main"}'

log 'granting contributor access: WRITE scripts (poison target), READ internal (flag1); NO prod-app collab'
api_put "/repos/$DEV_USER/freightpipe-scripts/collaborators/$CONTRIB_USER" '{"permission":"write"}'
api_put "/repos/$DEV_USER/freightpipe-internal/collaborators/$CONTRIB_USER" '{"permission":"read"}'

log 'generating the leaked PAT for contributor (capture the real token)'
LEAKED_TOKEN=$(as_git admin user generate-access-token --username "$CONTRIB_USER" --token-name stage0-leaked --scopes read:repository,write:repository --raw)
case "$LEAKED_TOKEN" in
  [0-9a-f]*) : ;;
  *) log "unexpected token output: $LEAKED_TOKEN"; exit 1 ;;
esac

seed_dir=$(mktemp -d /tmp/freightpipe-seed.XXXXXX)

log 'seeding freightpipe-scripts (build helper + app image source; token committed then removed in history)'
clone_repo freightpipe-scripts
mkdir -p scripts app
printf '# Freightpipe Scripts\n\nShared build inputs for Sparrow Freight CI.\n\nThe **prod-app** deploy pipeline fetches this repo every build: it runs `scripts/build.sh`\n(the build/test stage) and then packages `Dockerfile` + `app/` into the production image that\ngets pushed to the registry and deployed. The pipeline itself is locked down in prod-app, so all\nbuild logic and app source live here.\n' > README.md
cat > scripts/build.sh <<'EOF'
#!/bin/sh
set -eu
echo "[freightpipe] building ${APP_NAME:-prod-app}"
[ -f app/main.py ] && python3 -m py_compile app/main.py
echo '[freightpipe] build/test complete'
EOF
chmod 0755 scripts/build.sh
cat > Dockerfile <<'EOF'
FROM python:3.12-alpine
WORKDIR /app
COPY app/ /app/
EXPOSE 8080
CMD ["python3", "/app/main.py"]
EOF
cat > app/main.py <<'EOF'
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"Sparrow Freight: cargo moving safely\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
git add README.md scripts/build.sh Dockerfile app/main.py
git_commit 'build: shared build helper + production app image source' '2026-01-10T09:00:00Z'
cat > .env.deploy <<EOF
# temporary local deployment credentials -- do NOT commit
GITEA_URL=http://gitea:3000
GITEA_TOKEN=$LEAKED_TOKEN
EOF
git add .env.deploy
git_commit 'ops: add temporary deployment credentials' '2026-01-10T09:15:00Z'
git rm -q .env.deploy
git_commit 'security: remove committed deployment credentials' '2026-01-10T09:20:00Z'
git grep -q "$LEAKED_TOKEN" HEAD && { log 'token still in HEAD!'; exit 1; }
push_repo freightpipe-scripts

log 'seeding prod-app (protected; the TRUSTED pipeline: build shared inputs -> push image)'
clone_repo prod-app
printf '# Freightpipe Production App\n\nThe production deploy pipeline. Build inputs (build.sh, Dockerfile, app/)\nlive in dev/freightpipe-scripts; this pipeline packages them into the image and\npushes it to the registry. Deploys to prod happen over a signed webhook.\n' > README.md
cat > .woodpecker.yml <<'EOF'
skip_clone: true

steps:
  prepare:
    image: alpine/git:2.45.2
    commands:
      - git clone --depth 1 http://gitea:3000/dev/freightpipe-scripts.git .src
      - cp -r .src/app .src/scripts .src/Dockerfile ./
      - rm -rf .src
  build:
    image: python:3.12-alpine
    environment:
      USER_FLAG:
        from_secret: user_flag
      REGISTRY_TOKEN:
        from_secret: registry_token
      WEBHOOK_SECRET:
        from_secret: webhook_secret
      DEPLOY_URL:
        from_secret: deploy_url
    commands:
      - sh ./scripts/build.sh
  publish:
    image: woodpeckerci/plugin-kaniko
    settings:
      registry: registry:5000
      repo: prod-app
      tags: latest
      dockerfile: Dockerfile
      insecure: true
      skip_tls_verify: true
      insecure_registry: registry:5000
      username:
        from_secret: registry_user
      password:
        from_secret: registry_token
EOF
git add README.md .woodpecker.yml
git_commit 'ci: production deploy pipeline (build shared inputs -> image)' '2026-01-10T10:00:00Z'
push_repo prod-app

log 'seeding freightpipe-internal (flag1, contributor-readable)'
clone_repo freightpipe-internal
printf '# Freightpipe Internal\n\nPrivate operational notes.\n' > README.md
printf '%s\n' "$FLAG1" > FLAG1.txt
git add README.md FLAG1.txt
git_commit 'ops: stage-zero recovery marker' '2026-01-10T10:30:00Z'
push_repo freightpipe-internal

log 'protecting prod-app branches from direct pushes'
api_post "/repos/$DEV_USER/prod-app/branch_protections" '{"rule_name":"main","enable_push":false,"required_approvals":0}'
api_post "/repos/$DEV_USER/prod-app/branch_protections" '{"rule_name":"**","enable_push":false,"required_approvals":0}'

bootstrap_woodpecker_oauth
touch /data/.freightpipe-seeded; chown git:git /data/.freightpipe-seeded
log 'seed complete'
rm -rf "$seed_dir"; seed_dir=''
trap - INT TERM EXIT
wait "$gitea_pid"
