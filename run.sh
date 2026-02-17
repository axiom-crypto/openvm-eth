#!/bin/bash
#
# Usage: ./run.sh [OPTIONS]
#
# Options:
#   --mode <MODE>       Set the proving mode (default: prove-app)
#                       Valid modes: prove-app, prove-stark
#   --block <N>         Set the block number to prove (default: 23992138)
#   --cuda              Force CUDA acceleration (auto-detected if nvidia-smi available)
#
# Examples:
#   ./run.sh                          # Run with defaults
#   ./run.sh --mode prove-stark       # Run in prove-stark mode
#   ./run.sh --cuda --mode prove-app  # Force CUDA with prove-app mode
#

set -e

REPO_ROOT=$(git rev-parse --show-toplevel)
WORKDIR="$REPO_ROOT"

# =============== GPU memory usage monitoring ============================
GPU_LOG_FILE="$WORKDIR/gpu_memory_usage.csv"
GPU_MONITOR_INTERVAL="${GPU_MONITOR_INTERVAL:-5}"
GPU_MONITOR_PID=""
GPU_PEAK_FILE=""
GPU_MONITOR_ACTIVE=false

start_gpu_monitor() {
    if [ "$GPU_MONITOR_ACTIVE" = "true" ]; then
        return
    fi

    GPU_PEAK_FILE=$(mktemp)
    GPU_MONITOR_ACTIVE=true
    echo "timestamp,gpu_index,memory_used_mib" > "$GPU_LOG_FILE"
    echo 0 > "$GPU_PEAK_FILE"
    echo "Recording GPU memory usage to $GPU_LOG_FILE (interval: ${GPU_MONITOR_INTERVAL}s)."

    (
        set +e
        peak=0
        trap 'echo "$peak" > "$GPU_PEAK_FILE"; exit 0' TERM INT
        while true; do
            timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            if ! query=$(nvidia-smi --query-gpu=index,memory.used --format=csv,noheader,nounits 2>/dev/null); then
                echo "GPU monitor stopped: nvidia-smi is unavailable." >&2
                break
            fi
            while IFS=',' read -r gpu_idx mem_used; do
                [ -n "$gpu_idx" ] || continue
                gpu_idx=$(echo "$gpu_idx" | tr -d '[:space:]')
                mem_used=$(echo "$mem_used" | tr -d '[:space:]')
                if [ -z "$mem_used" ]; then
                    mem_used=0
                fi
                echo "$timestamp,$gpu_idx,$mem_used" >> "$GPU_LOG_FILE"
                if [ "$mem_used" -gt "$peak" ]; then
                    peak="$mem_used"
                    echo "$peak" > "$GPU_PEAK_FILE"
                fi
            done <<< "$query"
            sleep "$GPU_MONITOR_INTERVAL"
        done
        echo "$peak" > "$GPU_PEAK_FILE"
    ) &
    GPU_MONITOR_PID=$!
}

finalize_gpu_monitor() {
    if [ "$GPU_MONITOR_ACTIVE" != "true" ]; then
        return
    fi

    if [ -n "$GPU_MONITOR_PID" ]; then
        kill "$GPU_MONITOR_PID" >/dev/null 2>&1 || true
        wait "$GPU_MONITOR_PID" 2>/dev/null || true
        GPU_MONITOR_PID=""
    fi

    local peak="0"
    if [ -n "$GPU_PEAK_FILE" ] && [ -f "$GPU_PEAK_FILE" ]; then
        peak=$(cat "$GPU_PEAK_FILE")
        rm -f "$GPU_PEAK_FILE"
    fi

    echo "Peak GPU memory usage: ${peak:-0} MiB (logged to $GPU_LOG_FILE)"
    GPU_MONITOR_ACTIVE=false
}

trap finalize_gpu_monitor EXIT

NVIDIA_SMI_READY=false
if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi >/dev/null 2>&1; then
    NVIDIA_SMI_READY=true
fi

# Parse command-line arguments
MODE_OVERRIDE=""
PROFILE_OVERRIDE=""
BLOCK_NUMBER_OVERRIDE=""
USE_CUDA=false
CUDA_REASON=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE_OVERRIDE="$2"
            shift 2
            ;;
        --profile)
            PROFILE_OVERRIDE="$2"
            shift 2
            ;;
        --block)
            BLOCK_NUMBER_OVERRIDE="$2"
            shift 2
            ;;
        --cuda)
            USE_CUDA=true
            CUDA_REASON="requested via script argument"
            shift
            ;;
        --preimage-cache-nibbles)
            PREIMAGE_CACHE_NIBBLES="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

if [ "$USE_CUDA" = "false" ] && [ "$NVIDIA_SMI_READY" = "true" ]; then
    USE_CUDA=true
    CUDA_REASON="nvidia-smi detected a CUDA-capable GPU"
fi

if [ "$USE_CUDA" = "true" ]; then
    echo "Using CUDA acceleration ($CUDA_REASON)."
fi

if [ "$NVIDIA_SMI_READY" = "true" ]; then
    start_gpu_monitor "$GPU_MONITOR_INTERVAL"
else
    echo "nvidia-smi not detected; GPU memory monitoring disabled."
fi

MODE="${MODE_OVERRIDE:-execute}" # can be execute-host, execute, execute-metered, prove-app, prove-stark, or prove-evm (needs "evm-verify" feature)
echo "Benchmark Mode: $MODE"

mkdir -p rpc-cache
source .env

cd "$WORKDIR/bin/stateless-guest"
OPENVM_RUST_TOOLCHAIN=nightly-2026-01-01 cargo openvm build
mkdir -p ../reth-benchmark/elf
SRC="target/riscv32im-risc0-zkvm-elf/release/openvm-stateless-guest"
DEST="../reth-benchmark/elf/openvm-stateless-guest"

if [ ! -f "$DEST" ] || ! cmp -s "$SRC" "$DEST"; then
    cp "$SRC" "$DEST"
fi
cd "$WORKDIR"

# Map profile aliases and set target directory
case "${PROFILE_OVERRIDE:-release}" in
    dev|debug)
        PROFILE="dev"
        TARGET_DIR="debug"
        ;;
    *)
        PROFILE="${PROFILE_OVERRIDE:-release}"
        TARGET_DIR="$PROFILE"
        ;;
esac
FEATURES="metrics,jemalloc,unprotected"
BLOCK_NUMBER="${BLOCK_NUMBER_OVERRIDE:-23992138}"
TOOLCHAIN="+nightly-2026-01-01"
BIN_NAME="openvm-reth-benchmark"
MAX_SEGMENT_LENGTH=$((1 << 22))
SEGMENT_MAX_CELLS=1200000000
VPMM_PAGE_SIZE=$((4 << 20))
VPMM_PAGES=$((12 * $MAX_SEGMENT_LENGTH/ $VPMM_PAGE_SIZE))

if [ "$USE_CUDA" = "true" ]; then
    FEATURES="$FEATURES,cuda"
fi
if [ "$MODE" = "prove-evm" ]; then
    FEATURES="$FEATURES,evm-verify"
fi

arch=$(uname -m)
case $arch in
arm64|aarch64)
    RUSTFLAGS="-Ctarget-cpu=native"
    FEATURES="$FEATURES,tco"
    ;;
x86_64|amd64)
    RUSTFLAGS="-Ctarget-cpu=native"
    FEATURES="$FEATURES,aot"
    ;;
*)
echo "Unsupported architecture: $arch"
exit 1
;;
esac
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:10000,muzzy_decay_ms:10000,abort_conf:true"
RUSTFLAGS=$RUSTFLAGS cargo $TOOLCHAIN build --bin $BIN_NAME --profile=$PROFILE --no-default-features --features=$FEATURES
PARAMS_DIR="$HOME/.openvm/params/"

# Use target/debug if profile is dev
if [ "$PROFILE" = "dev" ]; then
    TARGET_DIR="debug"
else
    TARGET_DIR="$PROFILE"
fi

RUST_LOG="info,p3_=warn" OUTPUT_PATH="metrics.json" VPMM_PAGES=$VPMM_PAGES VPMM_PAGE_SIZE=$VPMM_PAGE_SIZE ./target/$TARGET_DIR/$BIN_NAME \
--kzg-params-dir $PARAMS_DIR \
--mode $MODE \
--block-number $BLOCK_NUMBER \
--rpc-url $RPC_1 \
--cache-dir rpc-cache \
--preimage-cache-nibbles ${PREIMAGE_CACHE_NIBBLES:-7} \
--app-log-blowup 1 \
--leaf-log-blowup 1 \
--internal-log-blowup 2 \
--root-log-blowup 3 \
--max-segment-length $MAX_SEGMENT_LENGTH \
--segment-max-cells $SEGMENT_MAX_CELLS \
--num-children-leaf 1 \
--num-children-internal 3
