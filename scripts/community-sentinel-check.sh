#!/usr/bin/env bash
# Hermetic Community Sentinel — 7 Contamination Gates
# Compares current default build against frozen baseline in .ci/community-baseline.json
# All measurements use: cargo build --release / cargo run --release (NO feature flags)
# Exit 0 = PASS, Exit 1 = FAIL
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

BASELINE=".ci/community-baseline.json"
if [ ! -f "$BASELINE" ]; then
    echo "ERROR: Baseline file $BASELINE not found. Run community-baseline.sh first."
    exit 1
fi

echo "══════════════════════════════════════════════════"
echo "  HERMETIC COMMUNITY SENTINEL"
echo "══════════════════════════════════════════════════"
echo ""

# Read baseline values
B_DEP=$(python3 -c "import json; print(json.load(open('$BASELINE'))['dep_count'])")
B_TEST=$(python3 -c "import json; print(json.load(open('$BASELINE'))['test_count'])")
B_CFG=$(python3 -c "import json; print(json.load(open('$BASELINE'))['cfg_count'])")
B_TMPL=$(python3 -c "import json; print(json.load(open('$BASELINE'))['template_count'])")
B_CMD=$(python3 -c "import json; print(json.load(open('$BASELINE'))['cmd_count'])")
B_SIZE=$(python3 -c "import json; print(json.load(open('$BASELINE'))['bin_size'])")

# Build Community profile
echo "Building Community profile (default features)..."
cargo build --release 2>&1 | tail -3
echo ""

FAILED=0

# S-1: Dependency count (exact — 0 new deps)
C_DEP=$(cargo tree --edges=normal 2>/dev/null | wc -l)
if [ "$C_DEP" -le "$B_DEP" ]; then
    echo "  S-1 PASS  dep_count: $C_DEP (baseline: $B_DEP)"
else
    echo "  S-1 FAIL  dep_count: $C_DEP > baseline: $B_DEP"
    FAILED=1
fi

# S-2: Build pass
if cargo build --release 2>&1 | grep -q 'error\['; then
    echo "  S-2 FAIL  build errors detected"
    FAILED=1
else
    echo "  S-2 PASS  build clean"
fi

# S-3: Test count (>= baseline, shrinkage blocked)
C_TEST=$(cargo test --release -- --list 2>&1 | grep ': test$' | wc -l)
if [ "$C_TEST" -ge "$B_TEST" ]; then
    echo "  S-3 PASS  test_count: $C_TEST (baseline: $B_TEST)"
else
    echo "  S-3 FAIL  test_count: $C_TEST < baseline: $B_TEST"
    FAILED=1
fi

# S-4: Feature flag count (INFO only)
C_CFG=$(grep -rn '#\[cfg(feature' crates/ --include='*.rs' | wc -l)
echo "  S-4 INFO  cfg_count: $C_CFG (baseline: $B_CFG)"

# S-5: Template count (exact) — actually count from compiled-in JSON
C_TMPL=$(python3 -c "import json; print(len(json.load(open('crates/hermetic/src/templates-community.json'))))")
if [ "$C_TMPL" -eq "$B_TMPL" ]; then
    echo "  S-5 PASS  template_count: $C_TMPL (baseline: $B_TMPL)"
else
    echo "  S-5 FAIL  template_count: $C_TMPL != baseline: $B_TMPL"
    FAILED=1
fi

# S-6: Command count (exact)
C_CMD=$(cargo run --release --bin hermetic -- --help 2>&1 | grep -cE '^  [a-z]')
if [ "$C_CMD" -eq "$B_CMD" ]; then
    echo "  S-6 PASS  cmd_count: $C_CMD (baseline: $B_CMD)"
else
    echo "  S-6 FAIL  cmd_count: $C_CMD != baseline: $B_CMD"
    FAILED=1
fi

# S-7: Binary size (<= baseline + 5%)
C_SIZE=$(stat -c%s target/release/hermetic)
MAX_SIZE=$(python3 -c "import math; print(math.ceil($B_SIZE * 1.05))")
if [ "$C_SIZE" -le "$MAX_SIZE" ]; then
    echo "  S-7 PASS  bin_size: $C_SIZE (baseline: $B_SIZE, max: $MAX_SIZE)"
else
    echo "  S-7 FAIL  bin_size: $C_SIZE > max: $MAX_SIZE (baseline: $B_SIZE + 5%)"
    FAILED=1
fi

echo ""
echo "══════════════════════════════════════════════════"
if [ "$FAILED" -eq 0 ]; then
    echo "  SENTINEL VERDICT: PASS"
else
    echo "  SENTINEL VERDICT: FAIL"
fi
echo "══════════════════════════════════════════════════"

exit $FAILED
