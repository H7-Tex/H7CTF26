#!/usr/bin/env bash
# Build the Time Capsule handout: a git repo where a secret was staged then unstaged before any
# commit - so it lives ONLY as a dangling blob in .git/objects, never in any commit and (after we
# drop the reflogs) not in the reflog either. Recoverable with `git fsck --lost-found`.
# A decoy dangling blob is added so the solver has to tell real from fake.
set -euo pipefail
FLAG="${FLAG:-H7CTF{d4ngl1ng_bl0b_n3v3r_c0mm1tt3d}}"
OUT="${1:-/tmp/time_capsule_build}"
rm -rf "$OUT"; mkdir -p "$OUT"; cd "$OUT"

export GIT_AUTHOR_NAME="mel" GIT_AUTHOR_EMAIL="mel@sparrow-freight.io"
export GIT_COMMITTER_NAME="mel" GIT_COMMITTER_EMAIL="mel@sparrow-freight.io"
export GIT_AUTHOR_DATE="2026-02-10T09:00:00" GIT_COMMITTER_DATE="2026-02-10T09:00:00"

git init -q -b main
git config gc.auto 0        # never prune dangling objects
git config user.name mel
git config user.email mel@sparrow-freight.io

# --- a plausible small project history ---
cat > README.md <<'EOF'
# sparrow-freight-api
Internal shipment tracking API. Do NOT commit secrets - use the vault.
EOF
mkdir -p app
cat > app/main.py <<'EOF'
from flask import Flask, jsonify
import os
app = Flask(__name__)

@app.get("/health")
def health():
    return jsonify(status="ok")

@app.get("/track/<awb>")
def track(awb):
    # TODO: wire up the carrier API using the token from the vault
    return jsonify(awb=awb, status="in_transit")

if __name__ == "__main__":
    app.run("0.0.0.0", int(os.environ.get("PORT", 8080)))
EOF
git add README.md app/main.py
git commit -q -m "initial: shipment tracking skeleton"

cat > .gitignore <<'EOF'
*.env
__pycache__/
EOF
git add .gitignore
git commit -q -m "add gitignore"

echo 'CARRIER_API_BASE=https://api.carrier.example' > app/config.py
git add app/config.py
git commit -q -m "config: carrier api base url"

# --- the accident: mel stages a real secrets file, then unstages it before committing ---
cat > carrier.env <<EOF
# production carrier credentials - DO NOT COMMIT
CARRIER_API_TOKEN=$FLAG
CARRIER_API_SECRET=b7f3c1a9e2d84f6b90care1a2b3c4d5e
EOF
git add -f carrier.env                 # blob is now written into .git/objects
git rm -q --cached carrier.env         # unstaged before any commit -> blob is now dangling
rm -f carrier.env                      # gone from the working tree too

# --- a decoy dangling blob (a fake/rotated token), to make fsck output ambiguous ---
printf 'CARRIER_API_TOKEN=H7CTF{this_token_was_rotated_not_the_flag}\n' | git hash-object -w --stdin >/dev/null

# one more innocent commit on top so the accident is "buried"
echo 'gunicorn==21.2.0' > requirements.txt
git add requirements.txt
git commit -q -m "pin gunicorn"

# drop reflogs so `git reflog` / `git log -g` won't reveal the staged blob -> must use fsck
rm -rf .git/logs

echo "built repo at $OUT"
git --no-pager log --oneline
echo "-- dangling objects --"
git fsck --no-reflogs 2>/dev/null | grep dangling || true
