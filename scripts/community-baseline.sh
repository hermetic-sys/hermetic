#!/usr/bin/env bash
# Hermetic Community Baseline Capture
# Captures metrics from the default (Community) build into .ci/community-baseline.json
# All measurements use: cargo build --release / cargo run --release (NO feature flags)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "=== Hermetic Community Baseline Capture ==="
echo "Working directory: $ROOT_DIR"

# Build Community profile (default features = [])
echo "Building Community profile..."
cargo build --release 2>&1 | tail -3

# Measurements
echo "Capturing metrics..."

DEP_COUNT=$(cargo tree --edges=normal 2>/dev/null | wc -l)
TEST_COUNT=$(cargo test --release -- --list 2>&1 | grep ': test$' | wc -l)
CFG_COUNT=$(grep -rn '#\[cfg(feature' crates/ --include='*.rs' | wc -l)
CMD_COUNT=$(cargo run --release --bin hermetic -- --help 2>&1 | grep -cE '^  [a-z]')
BIN_SIZE=$(stat -c%s target/release/hermetic)
HELP_HASH=$(cargo run --release --bin hermetic -- --help 2>&1 | sha256sum | cut -d' ' -f1)
FROZEN_AT=$(git rev-parse HEAD)

# Template count: read from community templates file (same source as sentinel S-5)
TEMPLATE_COUNT=$(python3 -c "import json; print(len(json.load(open('crates/hermetic/src/templates-community.json'))))")

# Write JSON
mkdir -p .ci
cat > .ci/community-baseline.json <<ENDJSON
{
  "dep_count": $DEP_COUNT,
  "test_count": $TEST_COUNT,
  "cfg_count": $CFG_COUNT,
  "template_count": $TEMPLATE_COUNT,
  "cmd_count": $CMD_COUNT,
  "bin_size": $BIN_SIZE,
  "help_hash": "$HELP_HASH",
  "frozen_at": "$FROZEN_AT"
}
ENDJSON

echo ""
echo "=== Baseline captured ==="
cat .ci/community-baseline.json
echo ""
echo "Saved to .ci/community-baseline.json"
