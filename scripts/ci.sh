#!/usr/bin/env bash
# scripts/ci.sh — D.U.M.E.R CI Check Script
# Runs: cargo fmt --check, cargo clippy -- -D warnings, cargo test, cargo deny check, cargo audit

set -euo pipefail

# Ensure Cargo bin directory is in process PATH if present
if [ -d "$HOME/.cargo/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.cargo/bin:"*) ;;
        *) export PATH="$HOME/.cargo/bin:$PATH" ;;
    esac
fi

echo "=================================================="
echo "   D.U.M.E.R CI Check Suite (POSIX / Bash)"
echo "=================================================="

if ! command -v cargo >/dev/null 2>&1; then
    echo "WARNING: [CI WARNING] 'cargo' is not installed or not found in PATH." >&2
    echo "WARNING: [CI WARNING] Skipping all cargo-dependent CI checks." >&2
    echo "CI finished with warnings (tools not installed)."
    exit 0
fi

echo "Using cargo at: $(command -v cargo)"

# 1. cargo fmt --check
echo ""
echo "--- [1/5] Checking code formatting (cargo fmt --check) ---"
if cargo fmt --version >/dev/null 2>&1; then
    cargo fmt --check
    echo "[PASS] cargo fmt --check"
else
    echo "WARNING: [CI WARNING] 'cargo fmt' component is not installed. Skipping formatting check." >&2
fi

# 2. cargo clippy -- -D warnings
echo ""
echo "--- [2/5] Running linter (cargo clippy -- -D warnings) ---"
if cargo clippy --version >/dev/null 2>&1; then
    cargo clippy --workspace --all-targets -- -D warnings
    echo "[PASS] cargo clippy"
else
    echo "WARNING: [CI WARNING] 'cargo clippy' component is not installed. Skipping clippy check." >&2
fi

# 3. cargo test
echo ""
echo "--- [3/5] Running tests (cargo test) ---"
cargo test --workspace
echo "[PASS] cargo test"

# 4. cargo deny check
echo ""
echo "--- [4/5] Checking dependencies and licenses (cargo deny check) ---"
if command -v cargo-deny >/dev/null 2>&1 || cargo deny --version >/dev/null 2>&1; then
    cargo deny check
    echo "[PASS] cargo deny check"
else
    echo "WARNING: [CI WARNING] 'cargo-deny' is not installed. Skipping dependency/license checks." >&2
fi

# 5. cargo audit
echo ""
echo "--- [5/5] Checking security advisories (cargo audit) ---"
if command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
    cargo audit
    echo "[PASS] cargo audit"
else
    echo "WARNING: [CI WARNING] 'cargo-audit' is not installed. Skipping vulnerability advisory check." >&2
fi

echo ""
echo "=================================================="
echo "   CI SUITE COMPLETE: ALL ACTIVE CHECKS PASSED"
echo "=================================================="
exit 0
