#!/usr/bin/env bash
# Makes Cargo.lock the part of the root Cargo.lock that the library needs, so that the library
# builds with the dependency versions (OpenVM commit included) of the root workspace, whose tests
# cover the accelerators. Run it after a change to the dependencies of the root workspace or of
# this crate; CI checks that Cargo.lock is up to date.
set -euo pipefail

cd "$(dirname "$0")"
cp ../../Cargo.lock Cargo.lock
# Removes the packages that the library doesn't need and adds the library itself.
cargo update --workspace --quiet

# Each package other than the library must be the root's: same name, version and source.
packages() {
  awk '/^\[\[package\]\]/ { if (name != "") print name, version, source; name = ""; source = "(path)" }
       /^name = / { name = $3 } /^version = / { version = $3 } /^source = / { source = $3 }
       END { if (name != "") print name, version, source }' "$1" | tr -d '"' | sort -u
}
OTHERS=$(comm -23 <(packages Cargo.lock) <(packages ../../Cargo.lock) | grep -v '^openvm-c-guest ' || true)
if [ -n "$OTHERS" ]; then
  echo "error: Cargo.lock has packages that the root Cargo.lock doesn't:" >&2
  echo "$OTHERS" >&2
  exit 1
fi
