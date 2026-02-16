#!/bin/bash
#
# Usage: ./run.sh [OPTIONS]
#
# Options:
#   --mode <MODE>       Set the proving mode (default: prove-app)
#                       Valid modes: prove-app, prove-stark, keygen, generate-vm-vkey
#   --generate-vm-vkey  Shortcut for --mode generate-vm-vkey
#   --profile <PROFILE> Set the Cargo build profile (default: profiling)
#                       Valid profiles: dev, release, profiling
#   --block <N>         Set the block number to prove (default: 23992138)
#   --app-l-skip <N>    Log of univariate skip domain size (default: 4)
#   --cuda              Force CUDA acceleration (auto-detected if nvidia-smi available)
#   --nsys              Run with nsys profiling and output summary stats
#   --<tool>            Run with compute-sanitizer --tool <tool> where tool is one of memcheck, synccheck, or racecheck
#
# Examples:
#   ./run.sh                              # Run with defaults
#   ./run.sh --mode prove-stark           # Run in prove-stark mode
#   ./run.sh --profile release            # Build with release profile
#   ./run.sh --cuda --mode prove-app      # Force CUDA with prove-app mode
#   ./run.sh --nsys --mode prove-app      # Run with nsys profiling
#   ./run.sh --block 23992138             # Prove a specific block
#   ./run.sh --mode generate-vm-vkey      # Generate reth.vm.vk locally
#   ./run.sh --generate-vm-vkey           # Same as above (shortcut)
#
set -e

REPO_ROOT=$(git rev-parse --show-toplevel)
WORKDIR=$REPO_ROOT

# TODO[jpw]: currently this needs to be built from openvm-eth:develop-new-hintstore because CLI is disabled on openvm v2 branch
DEST="$REPO_ROOT/bin/reth-benchmark/elf/openvm-stateless-guest"
if [ ! -f "$DEST" ]; then
    echo "Guest ELF not found: $DEST"
    exit 1
fi

cd $WORKDIR

# =============== GPU memory usage monitoring ============================
source "$REPO_ROOT/scripts/gpu_monitor.sh"
GPU_LOG_FILE="$WORKDIR/gpu_memory_usage.csv"
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
USE_NSYS=false
USE_NCU=false
COMPUTE_SANITIZER_ARGS=""

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
        --generate-vm-vkey)
            MODE_OVERRIDE="generate-vm-vkey"
            shift
            ;;
        --block)
            BLOCK_NUMBER_OVERRIDE="$2"
            shift 2
            ;;
        --leaf-log-blowup)
            LEAF_LOG_BLOWUP="$2"
            shift 2
            ;;
        --internal-log-blowup)
            INTERNAL_LOG_BLOWUP="$2"
            shift 2
            ;;
        --app-l-skip)
            APP_L_SKIP="$2"
            shift 2
            ;;
        --cuda)
            USE_CUDA=true
            CUDA_REASON="requested via --cuda script argument"
            shift
            ;;
        --nsys)
            USE_NSYS=true
            USE_CUDA=true
            CUDA_REASON="requested via --nsys script argument"
            shift
            ;;
        --ncu)
            USE_NCU=true
            if [[ $# -lt 2 ]]; then
            echo "Error: --ncu requires an argument" >&2
            exit 1
            fi
            ncu_kernel="$2"
            shift 2
            ;;
        --launch-skip)
            if [[ $# -lt 2 ]]; then
            echo "Error: --launch-skip requires an argument" >&2
            exit 1
            fi
            launch_skip="$2"
            shift 2
            ;;
        --launch-count)
            if [[ $# -lt 2 ]]; then
            echo "Error: --launch-count requires an argument" >&2
            exit 1
            fi
            launch_count="$2"
            shift 2
            ;;
        --memcheck)
            COMPUTE_SANITIZER_ARGS="compute-sanitizer --tool memcheck"
            shift
            ;;
        --synccheck)
            COMPUTE_SANITIZER_ARGS="compute-sanitizer --tool synccheck"
            shift
            ;;
        --racecheck)
            COMPUTE_SANITIZER_ARGS="compute-sanitizer --tool racecheck"
            shift
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

if [ "$NVIDIA_SMI_READY" = "true" ] && [ "$USE_NSYS" = "false" ]; then
    start_gpu_monitor "$GPU_LOG_FILE" "$GPU_MONITOR_INTERVAL"
elif [ "$USE_NSYS" = "true" ]; then
    echo "GPU memory monitoring disabled for nsys profiling."
else
    echo "nvidia-smi not detected; GPU memory monitoring disabled."
fi

mkdir -p rpc-cache
if [[ -f .env ]]; then
    # Optional convenience file for local runs.
    source .env
fi
if [[ -z "${RPC_1:-}" ]]; then
    echo "Missing RPC endpoint: set RPC_1 env var or create reth-bench/.env with RPC_1=..." >&2
    exit 1
fi
MODE="${MODE_OVERRIDE:-prove-app}" # can be prove-app, prove-stark, keygen, generate-vm-vkey

# Map profile aliases and set target directory
case "${PROFILE_OVERRIDE:-profiling}" in
    dev|debug)
        PROFILE="dev"
        TARGET_DIR="debug"
        ;;
    release)
        PROFILE="release"
        TARGET_DIR="release"
        ;;
    *)
        PROFILE="${PROFILE_OVERRIDE:-profiling}"
        TARGET_DIR="$PROFILE"
        ;;
esac
FEATURES="parallel,metrics,jemalloc,aot,unprotected"
BLOCK_NUMBER="${BLOCK_NUMBER_OVERRIDE:-23992138}"
# switch to +nightly-2025-08-19 if using tco
TOOLCHAIN="+nightly-2025-08-19" # "+stable"
BIN_NAME="openvm-reth-benchmark"
MAX_SEGMENT_LENGTH=$((1 << 22))
segment_max_memory=$((15 << 30))
export VPMM_PAGE_SIZE=$((4 << 20))
if [[ -z "${VPMM_PAGES:-}" ]] && [[ "$MODE" == "prove-stark" || "$MODE" == "prove-app" ]]; then
    export VPMM_PAGES=$((16 << 8)) # start with 16GB
fi
# Settings to turn off VPMM:
# VPMM_PAGE_SIZE=$((1<<35))
# VPMM_PAGES=0

if [ "$USE_CUDA" = "true" ]; then
    FEATURES="$FEATURES,cuda"
fi
# if [ "$MODE" = "prove-evm" ]; then
#     FEATURES="$FEATURES,evm-verify"
# fi

arch=$(uname -m)
case $arch in
arm64|aarch64)
    RUSTFLAGS="-Ctarget-cpu=native"
    ;;
x86_64|amd64)
    RUSTFLAGS="-Ctarget-cpu=native"
    ;;
*)
echo "Unsupported architecture: $arch"
exit 1
;;
esac
if [ "$USE_NSYS" = "false" ]; then
    export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:10000,muzzy_decay_ms:10000,abort_conf:true"
fi
if [[ "${OPENVM_BENCH_SKIP_BUILD:-0}" != "1" ]]; then
    RUSTFLAGS=$RUSTFLAGS cargo $TOOLCHAIN build --bin $BIN_NAME --profile=$PROFILE --no-default-features --features=$FEATURES
fi

BIN=$REPO_ROOT/target/$TARGET_DIR/$BIN_NAME

CONFIG_ARGS=""
if [[ -n $LEAF_LOG_BLOWUP ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --leaf-log-blowup ${LEAF_LOG_BLOWUP}"
fi
if [[ -n $INTERNAL_LOG_BLOWUP ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --internal-log-blowup ${INTERNAL_LOG_BLOWUP}"
fi
if [[ -n $APP_L_SKIP ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --app-l-skip ${APP_L_SKIP}"
fi

BIN_ARGS="--mode $MODE \
--max-segment-length $MAX_SEGMENT_LENGTH \
--segment-max-memory $segment_max_memory \
$CONFIG_ARGS"

if [ "$MODE" != "generate-vm-vkey" ]; then
    BIN_ARGS="$BIN_ARGS \
--block-number $BLOCK_NUMBER \
--rpc-url $RPC_1 \
--cache-dir rpc-cache"
fi
# TODO: aggregation tree (internal nodes)
# --num-children-leaf 1 \
# --num-children-internal 3

export RUST_LOG="info,p3_=warn"

if [ "$USE_NSYS" = "true" ]; then
    NSYS_OUTPUT="reth.nsys-rep"
    echo "Running with nsys profiling..."
    nsys profile --trace=cuda \
                 --force-overwrite=true \
                 -o "$NSYS_OUTPUT" \
                 $BIN $BIN_ARGS &
    nsys_pid=$!
    wait "$nsys_pid"

    echo "=== CUDA GPU Kernel Summary ==="
    nsys stats --report cuda_gpu_kern_sum "$NSYS_OUTPUT"
    echo "=== CUDA Memory Time Summary ==="
    nsys stats --report cuda_gpu_mem_time_sum "$NSYS_OUTPUT"
    echo "=== CUDA Memory Size Summary ==="
    nsys stats --report cuda_gpu_mem_size_sum "$NSYS_OUTPUT"
    echo "=== NCU Top Kernel Analysis ==="
    TOP_KERNEL=$(nsys stats --report cuda_gpu_kern_sum "$NSYS_OUTPUT" 2>/dev/null | \
        awk '/--------/{getline; print; exit}' | \
        sed -E 's/.*::([a-zA-Z_][a-zA-Z0-9_]*)[<(].*/\1/; t; s/.*[[:space:]]([a-zA-Z_][a-zA-Z0-9_]*)[<(].*/\1/')
    echo "Top kernel: $TOP_KERNEL"
elif [[ "$USE_NCU" == true ]]; then
    echo "[sudo] Running with Ncu..."
    NCU_OUTPUT="reth-${ncu_kernel}.ncu-rep"
    sudo env PATH=$PATH ncu \
    --target-processes all \
    --kernel-name "$ncu_kernel" \
    -f -o "${NCU_OUTPUT}" \
    --launch-skip "${launch_skip:-0}" \
    --launch-count "${launch_count:-4}" \
    --set full \
    $BIN $BIN_ARGS

    ncu -i "$NCU_OUTPUT" > "reth-${ncu_kernel}.txt"
else
    export OUTPUT_PATH="metrics.json"
    $COMPUTE_SANITIZER_ARGS $BIN $BIN_ARGS
fi
