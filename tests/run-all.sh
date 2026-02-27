#!/usr/bin/env bash
# Run all LAIA integration tests
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0; FAIL=0; SKIP=0

run_test() {
    local name="$1"; local script="$2"
    echo -n "  $name ... "
    if [[ ! -f "$script" ]]; then
        echo "SKIP (not found)"
        SKIP=$((SKIP+1))
        return
    fi
    if bash "$script" &>/dev/null; then
        echo "PASS ✅"
        PASS=$((PASS+1))
    else
        echo "FAIL ❌"
        FAIL=$((FAIL+1))
    fi
}

echo "=== LAIA Integration Tests ==="
echo ""
echo "── Configuration ──"
run_test "Package list exists"     "$TESTS_DIR/test_packages.sh"
run_test "Security config valid"   "$TESTS_DIR/test_security_config.sh"
run_test "OpenClaw config valid"   "$TESTS_DIR/test_openclaw_config.sh"
run_test "Build scripts exist"     "$TESTS_DIR/test_build_scripts.sh"
run_test "AI config valid"         "$TESTS_DIR/test_ai_config.sh"
run_test "Scripts are executable"  "$TESTS_DIR/test_scripts_executable.sh"

echo ""
echo "── Structure ──"
run_test "Required directories"    "$TESTS_DIR/test_structure.sh"
run_test "Documentation complete"  "$TESTS_DIR/test_docs.sh"
run_test "No secrets committed"    "$TESTS_DIR/test_no_secrets.sh"
run_test "i18n / licenses"         "$TESTS_DIR/test_licenses.sh"

echo ""
echo "═══════════════════════"
echo "Results: ${PASS} passed | ${FAIL} failed | ${SKIP} skipped"
echo "═══════════════════════"
[[ $FAIL -eq 0 ]]
