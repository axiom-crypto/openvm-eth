#!/bin/bash
set -e

REPO_ROOT=$(git rev-parse --show-toplevel)

USE_NSYS=false
USE_PERF=false
USE_COZ=false

while [[ $# -gt 0 ]]; do
  case $1 in
  --nsys)
    USE_NSYS=true
    shift
    ;;
  --perf)
    USE_PERF=true
    shift
    ;;
  --coz)
    USE_COZ=true
    shift
    ;;
  *)
    echo "Unknown argument: $1"
    exit 1
    ;;
  esac
done

export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:10000,muzzy_decay_ms:10000,abort_conf:true"

RUSTFLAGS="-C force-frame-pointers=yes -Ctarget-cpu=native"
TOOLCHAIN="+nightly-2026-01-18"

FEATURES="cuda,nvtx,parallel,jemalloc,metrics,halo2-asm"
if [ "$USE_COZ" = "true" ]; then
  FEATURES="$FEATURES,coz"
fi

echo "running: RUSTFLAGS=\"$RUSTFLAGS\" cargo \"$TOOLCHAIN\" build -p static-verifier-tracegen-arithonly --profile=profiling --no-default-features --features $FEATURES"

RUSTFLAGS="$RUSTFLAGS" cargo "$TOOLCHAIN" build \
  -p static-verifier-tracegen-arithonly \
  --profile=profiling \
  --no-default-features \
  --features "$FEATURES"

BIN="$REPO_ROOT/target/profiling/static-verifier-tracegen-arithonly"

MAX_MEM_SIZE=$((16 << 30))
export VPMM_PAGE_SIZE=$((4 << 20))
export VPMM_PAGES=$(($MAX_MEM_SIZE / $VPMM_PAGE_SIZE))

export OUTPUT_PATH="$REPO_ROOT/metrics-arithonly.json"

# Reuse the sibling binary's cache directory so we don't regenerate the pk/proof.
export STATIC_VERIFIER_CACHE_DIR="${STATIC_VERIFIER_CACHE_DIR:-$REPO_ROOT/bin/static-verifier-tracegen/cache}"

if [ "$USE_NSYS" = "true" ]; then
  NSYS_OUTPUT="$REPO_ROOT/tracegen-arithonly.nsys-rep"
  echo "Running with nsys profiling -> $NSYS_OUTPUT"
  nsys profile \
    --trace=cuda,nvtx,osrt \
    --cuda-memory-usage=true \
    --force-overwrite=true \
    -o "$NSYS_OUTPUT" \
    "$BIN"
elif [ "$USE_PERF" = "true" ]; then
  PERF_OUTPUT="$REPO_ROOT/tracegen-arithonly-perf.data"
  SAMPLY_DIR="$REPO_ROOT/samply_profile"
  SAMPLY_OUTPUT="$SAMPLY_DIR/tracegen-arithonly-profile.json.gz"
  mkdir -p "$SAMPLY_DIR"

  echo "Running with perf profiling -> $PERF_OUTPUT"
  perf record -F 4000 --call-graph=dwarf -g -o "$PERF_OUTPUT" -- "$BIN"

  echo "Converting perf.data with samply -> $SAMPLY_OUTPUT"
  samply import "$PERF_OUTPUT" --presymbolicate --save-only --output "$SAMPLY_OUTPUT"
  echo "Saved profile: $SAMPLY_OUTPUT"

  FIREFOX_PROFILER_URL=$(python3 "$REPO_ROOT/scripts/upload_firefox_profile.py" "$SAMPLY_OUTPUT") || true

  if [ -n "$FIREFOX_PROFILER_URL" ]; then
    echo "Firefox Profiler URL:"
    echo "$FIREFOX_PROFILER_URL"
  else
    echo "Warning: failed to upload profile to Firefox Profiler"
  fi
elif [ "$USE_COZ" = "true" ]; then
  COZ_OUTPUT="$REPO_ROOT/tracegen-arithonly.coz"
  export TRACEGEN_ITERS="${TRACEGEN_ITERS:-100}"
  echo "Running with coz causal profiler (TRACEGEN_ITERS=$TRACEGEN_ITERS) -> $COZ_OUTPUT"
  coz run --output="$COZ_OUTPUT" --- "$BIN"
  echo "coz profile written to $COZ_OUTPUT"
else
  export TRACEGEN_ITERS="${TRACEGEN_ITERS:-1}"
  "$BIN"
fi
