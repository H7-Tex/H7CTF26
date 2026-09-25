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

git_commit() {
  GIT_AUTHOR_DATE="$2" GIT_COMMITTER_DATE="$2" \
    git -c user.name='Sparrow Freight Dev' -c user.email='dev@sparrow-freight.local' commit -q -m "$1"
}
push_repo() {
  git remote add origin "http://$DEV_USER:$DEV_PASSWORD@127.0.0.1:3000/$DEV_USER/$1.git"
  git push -q -u origin main
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
  log 'already seeded'; trap - INT TERM EXIT; wait "$gitea_pid"; exit $?
fi

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
api_post '/user/repos' '{"name":"freightpipe-scripts","description":"Shared Freightpipe build helpers","private":false,"auto_init":false,"default_branch":"main"}'
api_post '/user/repos' '{"name":"prod-app","description":"Sparrow Freight production application","private":true,"auto_init":false,"default_branch":"main"}'
api_post '/user/repos' '{"name":"freightpipe-internal","description":"Private Freightpipe operations data","private":true,"auto_init":false,"default_branch":"main"}'

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

log 'seeding freightpipe-scripts (token committed then removed in history)'
mkdir -p "$seed_dir/freightpipe-scripts/scripts"; cd "$seed_dir/freightpipe-scripts"
git init -q -b main
printf '# Freightpipe Scripts\n\nShared build helpers for Sparrow Freight CI.\n\n`scripts/build.sh` is fetched and executed by the **prod-app** deploy pipeline on every build\n(the pipeline is locked down, so all shared logic lives here).\n' > README.md
cat > scripts/build.sh <<'EOF'
#!/bin/sh
set -eu
echo "[freightpipe] building ${APP_NAME:-prod-app}"
[ -f app/main.py ] && python3 -m py_compile app/main.py
echo '[freightpipe] build complete'
EOF
chmod 0755 scripts/build.sh
git add README.md scripts/build.sh
git_commit 'build: add shared application build helper' '2026-01-10T09:00:00Z'
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

log 'seeding prod-app (protected; .woodpecker.yml runs the TRUSTED shared build.sh)'
mkdir -p "$seed_dir/prod-app/app"; cd "$seed_dir/prod-app"
git init -q -b main
printf '# Freightpipe Production App\n\nBuilds consume the shared helper from dev/freightpipe-scripts.\n' > README.md
cat > .woodpecker.yml <<'EOF'
steps:
  prepare:
    image: alpine/git:2.45.2
    commands:
      - git clone --depth 1 http://gitea:3000/dev/freightpipe-scripts.git /tmp/s
      - mkdir -p scripts && cp /tmp/s/scripts/build.sh ./scripts/build.sh
  build:
    image: python:3.12-alpine
    commands:
      - sh ./scripts/build.sh
EOF
cat > app/main.py <<'EOF'
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"Sparrow Freight: cargo moving safely\n"
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
git add README.md .woodpecker.yml app/main.py
git_commit 'app: production service + shared build pipeline' '2026-01-10T10:00:00Z'
push_repo prod-app

log 'seeding freightpipe-internal (flag1, contributor-readable)'
mkdir -p "$seed_dir/freightpipe-internal"; cd "$seed_dir/freightpipe-internal"
git init -q -b main
printf '# Freightpipe Internal\n\nPrivate operational notes.\n' > README.md
printf '%s\n' "$FLAG1" > FLAG1.txt
git add README.md FLAG1.txt
git_commit 'ops: stage-zero recovery marker' '2026-01-10T10:30:00Z'
push_repo freightpipe-internal

log 'protecting prod-app branches from direct pushes'
api_post "/repos/$DEV_USER/prod-app/branch_protections" '{"rule_name":"main","enable_push":false,"required_approvals":0}'
api_post "/repos/$DEV_USER/prod-app/branch_protections" '{"rule_name":"**","enable_push":false,"required_approvals":0}'

touch /data/.freightpipe-seeded; chown git:git /data/.freightpipe-seeded
log 'seed complete'
rm -rf "$seed_dir"; seed_dir=''
trap - INT TERM EXIT
wait "$gitea_pid"
