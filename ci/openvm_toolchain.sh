#!/usr/bin/env bash
# Prints the OpenVM commit that a workspace's Cargo.lock locks and the OpenVM Rust toolchain of that
# commit, the one its `cargo openvm build` and SDK use, as lines for $GITHUB_ENV:
#
#   OPENVM_REV=<commit>
#   OPENVM_RUST_TOOLCHAIN=<toolchain>
#
# Usage: ci/openvm_toolchain.sh [workspace directory, by default the repository root]
set -euo pipefail

WORKSPACE="${1:-$(dirname "$0")/..}"

REVS=$(sed -n 's|^source = "git+https://github\.com/openvm-org/openvm\.git?[^#]*#\([0-9a-f]*\)"$|\1|p' \
  "$WORKSPACE/Cargo.lock" | sort -u)
if [ -z "$REVS" ] || [ "$(wc -l <<< "$REVS")" -ne 1 ]; then
  echo "error: $WORKSPACE/Cargo.lock doesn't lock exactly one OpenVM commit:" \
    "$(paste -sd ' ' <<< "${REVS:-none}")" >&2
  exit 1
fi

# The toolchain is openvm-build's DEFAULT_RUSTUP_TOOLCHAIN_NAME at that commit, in Cargo's checkout
# of the commit (a directory named after the commit's short hash).
MANIFESTS=$(cargo metadata --manifest-path "$WORKSPACE/Cargo.toml" --locked --format-version 1 |
  grep -oE "\"manifest_path\":\"[^\"]*/${REVS:0:7}[0-9a-f]*/[^\"]*\"" | cut -d '"' -f 4)
SOURCE=""
for manifest in $MANIFESTS; do
  dir=$(dirname "$manifest")
  if [ "$(git -C "$dir" rev-parse HEAD 2> /dev/null)" = "$REVS" ]; then
    SOURCE=$(git -C "$dir" rev-parse --show-toplevel)
    break
  fi
done
if [ -z "$SOURCE" ]; then
  echo "error: found no checkout of OpenVM $REVS in the metadata of $WORKSPACE" >&2
  exit 1
fi
TOOLCHAINS=$(grep -rhoE --include='*.rs' 'DEFAULT_RUSTUP_TOOLCHAIN_NAME: &str = "[^"]+"' "$SOURCE" |
  cut -d '"' -f 2 | sort -u)
if [ -z "$TOOLCHAINS" ] || [ "$(wc -l <<< "$TOOLCHAINS")" -ne 1 ]; then
  echo "error: OpenVM $REVS doesn't define exactly one DEFAULT_RUSTUP_TOOLCHAIN_NAME:" \
    "$(paste -sd ' ' <<< "${TOOLCHAINS:-none}")" >&2
  exit 1
fi

echo "OPENVM_REV=$REVS"
echo "OPENVM_RUST_TOOLCHAIN=$TOOLCHAINS"
