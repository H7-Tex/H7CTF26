#!/usr/bin/env bash
# Solve for Time Capsule. The flag was staged then unstaged before any commit, so `git log` is
# clean and (reflogs were dropped) `git reflog` shows nothing. But `git add` already wrote the blob
# into .git/objects, where it now sits unreferenced. `git fsck` lists such dangling objects.
set -euo pipefail
REPO="${1:-sparrow-freight-api}"
cd "$REPO"

echo "[*] normal history is clean:"
git --no-pager log --oneline

echo "[*] dangling objects (git fsck):"
git fsck --lost-found 2>/dev/null | grep dangling

echo "[*] dumping each dangling blob - the real one is the production secrets file:"
for h in $(git fsck 2>/dev/null | awk '/dangling blob/{print $3}'); do
    echo "--- $h ---"
    git cat-file -p "$h"
done
# the real flag is CARRIER_API_TOKEN in the blob that also carries CARRIER_API_SECRET;
# the other dangling blob is a rotated/decoy token.
