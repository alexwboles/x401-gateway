#!/usr/bin/env bash
# x401-gateway smoke: unit discovery + end-to-end. Exit non-zero on any failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pass=0
fail=0

run_suite() {
    local name="$1"; shift
    echo "=== $name ==="
    if "$@" 2>&1; then
        echo "--- PASS: $name"
        pass=$((pass + 1))
    else
        echo "--- FAIL: $name"
        fail=$((fail + 1))
    fi
}

run_suite "unit tests (discover tests/test_*.py)" \
    python3 -m unittest discover -s tests -p "test_*.py"
run_suite "end-to-end tests (tests/e2e.py)" \
    python3 tests/e2e.py

echo
echo "suites passed: $pass, failed: $fail"
if [ "$fail" -ne 0 ]; then
    echo "SMOKE: FAIL"
    exit 1
fi
echo "SMOKE: PASS"
