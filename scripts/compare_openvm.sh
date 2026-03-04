#!/bin/bash
set -euo pipefail

# Usage: ./compare_openvm.sh <base_ref> <target_ref> [--mode <mode>] [--block <N>] [--no-cache] [-- <extra run.sh args>]
#
# Accepts branch names, tag names, or commit SHAs.
#
# Compares benchmarks between two openvm revisions by:
#   1. Resolving refs and stark-backend revisions
#   2. Patching .cargo/config.toml for base, building + running benchmark
#   3. Patching .cargo/config.toml for target, building + running benchmark
#   4. Comparing results with openvm-prof
#
# Output:
#   Comparison report: .bench_metrics/target_metrics.md
#
# Caching:
#   Benchmark metrics are cached in .bench_metrics/ keyed by rev+mode+block
#   (e.g. cd26999ccd3a_prove-stark.json or cd26999ccd3a_prove-app_block21345144.json).
#   Re-runs skip already-computed benchmarks.
#   Use --no-cache to force re-running all benchmarks.
#
# Examples:
#   ./compare_openvm.sh develop-v2.0.0-beta chore/interaction-weight
#   ./compare_openvm.sh develop-v2.0.0-beta chore/interaction-weight --mode prove-stark
#   ./compare_openvm.sh cd26999ccd3a 3facb8a8a020 --mode prove-stark
#   ./compare_openvm.sh develop-v2.0.0-beta 3facb8a8a020 --mode prove-app --block 21345144

REPO_ROOT=$(git rev-parse --show-toplevel)
RESULTS_DIR="$REPO_ROOT/.bench_metrics"
TEMPLATE="$REPO_ROOT/.cargo/config.template.toml"

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE="prove-app"
BLOCK=""
EXTRA_ARGS=""
USE_CACHE=true

# ── Parse arguments ───────────────────────────────────────────────────────────
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <base_ref> <target_ref> [--mode <mode>] [--block <N>] [--no-cache] [-- <extra run.sh args>]"
    exit 1
fi

BASE_BRANCH="$1"
TARGET_BRANCH="$2"
shift 2

while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --block)
            BLOCK="$2"
            shift 2
            ;;
        --no-cache)
            USE_CACHE=false
            shift
            ;;
        --)
            shift
            EXTRA_ARGS="$*"
            break
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

RUN_ARGS="--mode $MODE"
if [[ -n "$BLOCK" ]]; then
    RUN_ARGS="$RUN_ARGS --block $BLOCK"
fi
if [[ -n "$EXTRA_ARGS" ]]; then
    RUN_ARGS="$RUN_ARGS $EXTRA_ARGS"
fi

mkdir -p "$RESULTS_DIR"

echo "============================================================"
echo " OpenVM Branch Comparison"
echo "============================================================"
echo " Base:   $BASE_BRANCH"
echo " Target: $TARGET_BRANCH"
echo " Mode:   $MODE"
echo " Args:   $RUN_ARGS"
echo "============================================================"
echo

# ── Step 1: Resolve revisions ────────────────────────────────────────────────
# Accepts a branch name, tag name, or commit SHA.
resolve_rev() {
    local ref="$1"
    local rev

    # Try as a branch
    rev=$(git ls-remote https://github.com/openvm-org/openvm.git "refs/heads/$ref" | cut -f1)
    if [[ -n "$rev" ]]; then echo "$rev"; return; fi

    # Try as a tag
    rev=$(git ls-remote https://github.com/openvm-org/openvm.git "refs/tags/$ref" | cut -f1)
    if [[ -n "$rev" ]]; then echo "$rev"; return; fi

    # Assume it's a commit SHA
    echo "$ref"
}

echo ">>> Resolving revisions..."

BASE_REV=$(resolve_rev "$BASE_BRANCH") || exit 1
TARGET_REV=$(resolve_rev "$TARGET_BRANCH") || exit 1

echo "  Base   ($BASE_BRANCH):   $BASE_REV"
echo "  Target ($TARGET_BRANCH): $TARGET_REV"
echo

# ── Step 2: Get STARK_BACKEND_REV for each ───────────────────────────────────
get_stark_backend_rev() {
    local openvm_rev="$1"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" RETURN

    git clone --quiet --depth 1 https://github.com/openvm-org/openvm.git "$tmp_dir" 2>/dev/null
    (cd "$tmp_dir" && git fetch --quiet --depth 1 origin "$openvm_rev" 2>/dev/null && git checkout --quiet FETCH_HEAD 2>/dev/null)
    (cd "$tmp_dir" && cargo metadata --format-version=1 2>/dev/null | jq -r '.packages[] | select(.name=="openvm-stark-sdk") | .source | split("#") | .[1]')
}

echo ">>> Resolving STARK_BACKEND_REV for base..."
BASE_STARK_REV=$(get_stark_backend_rev "$BASE_REV")
echo "  Base STARK_BACKEND_REV: $BASE_STARK_REV"

echo ">>> Resolving STARK_BACKEND_REV for target..."
TARGET_STARK_REV=$(get_stark_backend_rev "$TARGET_REV")
echo "  Target STARK_BACKEND_REV: $TARGET_STARK_REV"
echo

# ── Helper: patch config.toml ────────────────────────────────────────────────
patch_config() {
    local openvm_rev="$1"
    local stark_rev="$2"

    sed "s|\\\$STARK_BACKEND_REV|${stark_rev}|g" "$TEMPLATE" > /tmp/_config_patch_tmp.toml
    sed "s|\\\$OPENVM_REV|${openvm_rev}|g" /tmp/_config_patch_tmp.toml > "$REPO_ROOT/.cargo/config.toml"
    rm -f /tmp/_config_patch_tmp.toml
}

# ── Helper: cache key for a benchmark run ────────────────────────────────────
metrics_cache_path() {
    local openvm_rev="$1"
    local short_rev="${openvm_rev:0:12}"
    local cache_name="${short_rev}_${MODE}"
    if [[ -n "$BLOCK" ]]; then
        cache_name="${cache_name}_block${BLOCK}"
    fi
    echo "$RESULTS_DIR/${cache_name}.json"
}

# ── Helper: run benchmark (with cache) ───────────────────────────────────────
run_benchmark() {
    local label="$1"
    local openvm_rev="$2"
    local stark_rev="$3"
    local metrics_file="$4"
    local cache_file
    cache_file=$(metrics_cache_path "$openvm_rev")

    if [[ "$USE_CACHE" == true && -f "$cache_file" ]]; then
        echo "============================================================"
        echo " CACHED: $label benchmark"
        echo "   openvm rev:  $openvm_rev"
        echo "   cache file:  $cache_file"
        echo "============================================================"
        cp "$cache_file" "$metrics_file"
        echo ">>> Using cached metrics. Skipping benchmark run."
        echo
        return
    fi

    echo "============================================================"
    echo " Running $label benchmark"
    echo "   openvm rev:  $openvm_rev"
    echo "   stark rev:   $stark_rev"
    echo "   metrics out: $metrics_file"
    echo "============================================================"

    # Patch
    echo ">>> Patching .cargo/config.toml..."
    patch_config "$openvm_rev" "$stark_rev"

    # Update Cargo.lock
    echo ">>> Updating Cargo.lock..."
    cargo update 2>&1 | tail -5

    # Build + run
    echo ">>> Building and running benchmark ($RUN_ARGS)..."
    cd "$REPO_ROOT"
    # shellcheck disable=SC2086
    ./run.sh $RUN_ARGS

    # Save metrics to both the output path and the cache
    cp "$REPO_ROOT/metrics.json" "$metrics_file"
    cp "$REPO_ROOT/metrics.json" "$cache_file"
    echo ">>> $label benchmark complete. Metrics saved to $metrics_file (cached as $cache_file)"
    echo
}

# ── Step 3: Run base benchmark ────────────────────────────────────────────────
BASE_METRICS="$RESULTS_DIR/base_metrics.json"
run_benchmark "BASE ($BASE_BRANCH)" "$BASE_REV" "$BASE_STARK_REV" "$BASE_METRICS"

# ── Step 4: Run target benchmark ─────────────────────────────────────────────
TARGET_METRICS="$RESULTS_DIR/target_metrics.json"
run_benchmark "TARGET ($TARGET_BRANCH)" "$TARGET_REV" "$TARGET_STARK_REV" "$TARGET_METRICS"

# ── Step 5: Compare ──────────────────────────────────────────────────────────
echo "============================================================"
echo " Comparing results"
echo "============================================================"

# Install openvm-prof if needed
if ! command -v openvm-prof >/dev/null 2>&1; then
    echo ">>> Installing openvm-prof..."
    cargo install --git https://github.com/openvm-org/openvm.git --profile=dev --force openvm-prof 2>&1 | tail -3
fi

cd "$RESULTS_DIR"
openvm-prof --json-paths target_metrics.json --prev-json-paths base_metrics.json

MD_PATH="$RESULTS_DIR/target_metrics.md"

echo
echo "============================================================"
echo " Comparison complete!"
echo "============================================================"
echo " Base:   $BASE_BRANCH ($BASE_REV)"
echo " Target: $TARGET_BRANCH ($TARGET_REV)"
echo " Mode:   $MODE"
echo " Report: $MD_PATH"
echo "============================================================"
echo
echo "Summary (first 20 lines):"
head -20 "$MD_PATH"
