#!/usr/bin/env bash
set -euo pipefail

# Must match openvm-certified-verifier's generated C and Lean runtime ABI.
if ! command -v elan >/dev/null 2>&1; then
    curl -sSf https://elan.lean-lang.org/elan-init.sh | sh -s -- -y --default-toolchain none
    export PATH="${ELAN_HOME:-$HOME/.elan}/bin:$PATH"
    if [[ -n "${GITHUB_PATH:-}" ]]; then
        echo "${ELAN_HOME:-$HOME/.elan}/bin" >> "$GITHUB_PATH"
    fi
fi
elan toolchain install leanprover/lean4:v4.26.0
