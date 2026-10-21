#!/usr/bin/env bash
# 70-gitea-seed.sh - seed Gitea: org, repos, deploy keys, per-team webhooks
# run after VMs are up and Gitea is configured (cloud-init must have finished).
# GITEA_TOKEN must be exported (ops VM reads it from ~/.secrets/gitea-admin-token).
set -euo pipefail
source "$(dirname "$0")/lib.sh"

GITEA_URL=http://10.60.201.30:3000
: "${GITEA_TOKEN:?set GITEA_TOKEN (gitea admin token)}"
WEBHOOK_SECRET=$(cat "$SCRIPT_DIR/secrets/webhook-secret" 2>/dev/null || \
  openssl rand -hex 24 | tee "$SCRIPT_DIR/secrets/webhook-secret")

g() { curl -fsS -H "Authorization: token $GITEA_TOKEN" -H "Content-Type: application/json" "$@"; }

# --- org ---
g -X POST "$GITEA_URL/api/v1/orgs" \
  -d '{"username":"h7ctf","full_name":"H7CTF Finals","visibility":"private"}' 2>/dev/null || true
echo "org h7ctf: ok"

# services list; finals-team owns the exact repo names
SERVICES=(service1 service2 service3)  # placeholder - finals-3 fills this in

seed_team() {
  local t=$1 tt; tt=$(printf %02d "$t")
  local team="team$tt"

  # create team user if not exists (workbench SSH key is added by dist-creds.sh later)
  g -X POST "$GITEA_URL/api/v1/admin/users" \
    -d "{\"username\":\"$team\",\"password\":\"$(openssl rand -hex 12)\",\"email\":\"$team@internal.h7ctf\",\"must_change_password\":false}" \
    2>/dev/null || true

  for svc in "${SERVICES[@]}"; do
    local repo="${team}-${svc}"
    # create repo under org
    g -X POST "$GITEA_URL/api/v1/orgs/h7ctf/repos" \
      -d "{\"name\":\"$repo\",\"description\":\"$team $svc\",\"private\":true,\"auto_init\":true,\"default_branch\":\"main\"}" \
      2>/dev/null || true

    # give team push access
    g -X PUT "$GITEA_URL/api/v1/repos/h7ctf/$repo/collaborators/$team" \
      -d '{"permission":"write"}' 2>/dev/null || true

    # webhook: prod box deployer listens on :9000/hook; triggered on push to main
    g -X POST "$GITEA_URL/api/v1/repos/h7ctf/$repo/hooks" \
      -d "{
        \"type\":\"gitea\",
        \"config\":{\"url\":\"http://10.60.$t.2:9000/hook/$repo\",\"content_type\":\"json\",\"secret\":\"$WEBHOOK_SECRET\"},
        \"events\":[\"push\"],
        \"active\":true
      }" 2>/dev/null || true

    echo "repo h7ctf/$repo: user+webhook ok"
  done
}

export GITEA_URL GITEA_TOKEN WEBHOOK_SECRET
export -f g seed_team

for t in $(seq 1 "$N"); do
  seed_team "$t" &
done
wait

echo "gitea seeded. distribute deploy keys with ops/dist-creds.sh."
echo "WEBHOOK_SECRET written to $SCRIPT_DIR/secrets/webhook-secret"
