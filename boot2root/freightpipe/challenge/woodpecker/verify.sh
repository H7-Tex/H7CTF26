#!/bin/sh
# Milestone 2 live checks. Prints one PASS/FAIL result per required contract.
set -u

failures=0
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; failures=$((failures + 1)); }

woodpecker_port=${WOODPECKER_PORT:-8000}
woodpecker_verify_url=${WOODPECKER_VERIFY_URL:-http://127.0.0.1:$woodpecker_port}

if curl -fsS "$woodpecker_verify_url/healthz" >/dev/null 2>&1; then
  pass "woodpecker-server is reachable at $woodpecker_verify_url"
else
  fail "woodpecker-server is not reachable at $woodpecker_verify_url"
fi

if docker compose exec -T woodpecker-server sh -c \
  '. /oauth/woodpecker.env && test -n "$WOODPECKER_GITEA_CLIENT" && test -n "$WOODPECKER_GITEA_SECRET"' \
  >/dev/null 2>&1; then
  pass 'woodpecker-server can read the Gitea OAuth credentials'
else
  fail 'woodpecker-server cannot read the Gitea OAuth credentials'
fi

agent_logs=$(docker compose logs --no-color woodpecker-agent 2>&1)
if printf '%s\n' "$agent_logs" | grep -Eq 'agent registered with ID|polling new (steps|workflows)'; then
  pass 'woodpecker-agent registered with woodpecker-server'
else
  fail 'woodpecker-agent logs do not show a successful registration'
fi

if docker compose exec -T woodpecker-server wget -q -O /dev/null \
  http://gitea:3000/api/healthz >/dev/null 2>&1; then
  pass 'woodpecker-server can reach Gitea'
else
  fail 'woodpecker-server cannot reach Gitea'
fi

exit "$failures"
