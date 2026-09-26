#!/bin/sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$1"
STAGE="$(mktemp -d)"
cp "$HERE/target/sealer" "$STAGE/sealer"
( cd "$HERE/interrogator" && CARGO_TARGET_DIR="$STAGE/t" cargo build --release >/dev/null 2>&1 )
cp "$STAGE/t/release/interrogator" "$STAGE/simulator"
cp "$HERE/interrogator/asm.py" "$STAGE/asm.py"
cp "$ROOT/handout/ISA_SPEC.md" "$STAGE/ISA_SPEC.md"
cp "$ROOT/handout/example.tqa" "$STAGE/example.tqa"
strip "$STAGE/sealer" "$STAGE/simulator" 2>/dev/null || true
( cd "$STAGE" && zip -q -r "$OUT" sealer simulator asm.py ISA_SPEC.md example.tqa )
rm -rf "$STAGE"
echo "handout -> $OUT"
