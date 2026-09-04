#!/bin/bash
#
# Usage: ./run.sh [OPTIONS]
#
# Options:
#   --mode <MODE>       Set the proving mode (default: prove-app)
#                       Valid modes: prove-app, prove-stark, prove-root, prove-evm, keygen, keygen-root, generate-vm-vkey
#   --generate-vm-vkey  Shortcut for --mode generate-vm-vkey
#   --profile <PROFILE> Set the Cargo build profile (default: profiling)
#                       Valid profiles: dev, release, profiling
#   --block <N>         Set the block number to prove (default: 24001988)
#   --app-log-blowup <N>
#   --app-l-skip <N>    Log of univariate skip domain size (default: 4)
#   --leaf-log-blowup <N>
#   --internal-log-blowup <N>
#   --root-log-blowup <N>
#   --num-children-leaf <N>
#   --num-children-internal <N>
#   --segment-max-memory <N>
#   --cuda              Force CUDA acceleration (auto-detected if nvidia-smi available)
#   --exec-mode <MODE>  Select the OpenVM execution backend: interpreter | tco | rvr.
#                       Defaults to rvr.
#                       rvr requires clang-22 and lld on PATH.
#   --perf              Run with perf + samply host profiling and upload to Firefox Profiler
#   --nsys              Run with nsys profiling and output summary stats
#   --nsys-gpu-metrics  Include nsys GPU hardware metrics (`--gpu-metrics-devices=all`).
#                       Higher overhead; use for hardware-counter analysis, not baseline timing.
#   --<tool>            Run with compute-sanitizer --tool <tool> where tool is one of memcheck, synccheck, or racecheck
#   --proof-cache <DIR> Directory to cache the intermediate stark proof for prove-root mode.
#                       If set, the stark proof is stored at <DIR>/stark.bitcode and reused
#                       on subsequent runs. If unset, no proof caching is performed.
#
# Examples:
#   ./run.sh                              # Run with defaults
#   ./run.sh --mode prove-stark           # Run in prove-stark mode
#   ./run.sh --profile release            # Build with release profile
#   ./run.sh --cuda --mode prove-app      # Force CUDA with prove-app mode
#   ./run.sh --perf --mode execute         # Run with host profiling (Firefox Profiler link)
#   ./run.sh --nsys --mode prove-app      # Run with nsys profiling
#   ./run.sh --nsys --nsys-gpu-metrics --mode prove-app
#   ./run.sh --block 24001988             # Prove a specific block
#   ./run.sh --mode generate-vm-vkey      # Generate reth.vm.vk locally
#   ./run.sh --generate-vm-vkey           # Same as above (shortcut)
#
set -e

REPO_ROOT=$(git rev-parse --show-toplevel)
WORKDIR=$REPO_ROOT
RUST_TOOLCHAIN=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$REPO_ROOT/rust-toolchain.toml")

DEST="$REPO_ROOT/bin/reth-benchmark/elf/openvm-stateless-guest"

build_openvm_guest_elf() {
    cd "$REPO_ROOT/bin/stateless-guest"
    cargo openvm build
    mkdir -p ../reth-benchmark/elf
    SRC="target/riscv64im-unknown-openvm-elf/release/openvm-stateless-guest"
    if [ ! -f "$DEST" ] || ! cmp -s "$SRC" "$DEST"; then
        cp "$SRC" "$DEST"
    fi
    cd "$WORKDIR"
}

cd "$WORKDIR"

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
EXEC_MODE=""
USE_PERF=false
USE_NSYS=false
USE_NSYS_GPU_METRICS=false
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
        --segment-max-memory)
            SEGMENT_MAX_MEMORY="$2"
            shift 2
            ;;
        --app-log-blowup)
            APP_LOG_BLOWUP="$2"
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
        --root-log-blowup)
            ROOT_LOG_BLOWUP="$2"
            shift 2
            ;;
        --num-children-leaf)
            NUM_CHILDREN_LEAF="$2"
            shift 2
            ;;
        --num-children-internal)
            NUM_CHILDREN_INTERNAL="$2"
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
        --exec-mode)
            case "${2:-}" in
                interpreter|tco|rvr)
                    EXEC_MODE="$2"
                    ;;
                *)
                    echo "Error: --exec-mode requires one of: interpreter, tco, rvr (got '${2:-}')" >&2
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --perf)
            USE_PERF=true
            shift
            ;;
        --nsys)
            USE_NSYS=true
            USE_CUDA=true
            CUDA_REASON="requested via --nsys script argument"
            shift
            ;;
        --nsys-gpu-metrics)
            USE_NSYS_GPU_METRICS=true
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
        --proof-cache)
            PROOF_CACHE="$2"
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

if [ "$USE_NSYS_GPU_METRICS" = "true" ] && [ "$USE_NSYS" = "false" ]; then
    echo "Error: --nsys-gpu-metrics requires --nsys" >&2
    exit 1
fi

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
case "${PROFILE_OVERRIDE:-release}" in
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
FEATURES="parallel,metrics,jemalloc,unprotected"
BLOCK_NUMBER="${BLOCK_NUMBER_OVERRIDE:-24001988}"
TOOLCHAIN="+$RUST_TOOLCHAIN"
BIN_NAME="openvm-reth-benchmark"
export VPMM_PAGE_SIZE=$((4 << 20))
if [[ -z "${VPMM_PAGES:-}" ]] && [[ "$MODE" == "prove-stark" || "$MODE" == "prove-app" || "$MODE" == "prove-evm" ]]; then
    export VPMM_PAGES=$((16 << 8)) # start with 16GB
fi
# Settings to turn off VPMM:
# VPMM_PAGE_SIZE=$((1<<35))
# VPMM_PAGES=0

if [ "$USE_CUDA" = "true" ]; then
    FEATURES="$FEATURES,cuda,halo2-gpu"
fi
if [ "$USE_NSYS" = "true" ]; then
    FEATURES="$FEATURES,nvtx"
fi
if [ "$MODE" = "prove-evm" ] || [ "$MODE" = "prove-root" ] || [ "$MODE" = "keygen-root" ]; then
    FEATURES="$FEATURES,evm-verify"
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; then
        FEATURES="$FEATURES,halo2-asm"
    fi
fi

# `keygen-root` is a shell-level alias: enable evm-verify (handled above) and pass --mode keygen
# to the binary. The keygen branch then additionally writes <output_dir>/root.pk when evm-verify
# is compiled in.
if [ "$MODE" = "keygen-root" ]; then
    MODE="keygen"
fi

arch=$(uname -m)
case $arch in
arm64|aarch64)
    RUSTFLAGS="-Ctarget-cpu=native"
    if [ -z "$EXEC_MODE" ]; then
        EXEC_MODE="rvr"
    fi
    ;;
x86_64|amd64)
    RUSTFLAGS="-Ctarget-cpu=native"
    if [ -z "$EXEC_MODE" ]; then
        EXEC_MODE="rvr"
    fi
    ;;
*)
echo "Unsupported architecture: $arch"
exit 1
;;
esac
case "$EXEC_MODE" in
    interpreter)
        # default interpreted execution; no extra backend feature
        ;;
    tco)
        FEATURES="$FEATURES,tco"
        ;;
    rvr)
        FEATURES="$FEATURES,rvr"
        missing=()
        command -v clang-22 >/dev/null 2>&1 || missing+=("clang-22")
        command -v lld      >/dev/null 2>&1 || missing+=("lld")
        if [ "${#missing[@]}" -gt 0 ]; then
            echo "Error: --exec-mode rvr requires the following tools on PATH: ${missing[*]}" >&2
            echo "       Install them or rerun with --exec-mode interpreter." >&2
            exit 1
        fi
        ;;
esac
if [ "$USE_PERF" = "true" ] || [ "$USE_NSYS" = "true" ]; then
    RUSTFLAGS="$RUSTFLAGS -C force-frame-pointers=yes"
    # Default to profiling profile for host profiling if not overridden
    if [ -z "$PROFILE_OVERRIDE" ]; then
        PROFILE="profiling"
        TARGET_DIR="profiling"
    fi
fi
if [ "$USE_NSYS" = "false" ]; then
    export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:10000,muzzy_decay_ms:10000,abort_conf:true"
fi
if [[ "${OPENVM_BENCH_SKIP_BUILD:-0}" != "1" ]]; then
    build_openvm_guest_elf
    RUSTFLAGS=$RUSTFLAGS cargo $TOOLCHAIN build --bin $BIN_NAME --profile=$PROFILE --no-default-features --features=$FEATURES
fi

BIN=$REPO_ROOT/target/$TARGET_DIR/$BIN_NAME

CONFIG_ARGS=""
if [[ -n $APP_LOG_BLOWUP ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --app-log-blowup ${APP_LOG_BLOWUP}"
fi
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
if [[ -n $ROOT_LOG_BLOWUP ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --root-log-blowup ${ROOT_LOG_BLOWUP}"
fi
if [[ -n $NUM_CHILDREN_LEAF ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --num-children-leaf ${NUM_CHILDREN_LEAF}"
fi
if [[ -n $NUM_CHILDREN_INTERNAL ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --num-children-internal ${NUM_CHILDREN_INTERNAL}"
fi
if [[ -n $PROOF_CACHE ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --proof-cache ${PROOF_CACHE}"
fi
if [[ -n $SEGMENT_MAX_MEMORY ]]
then
    CONFIG_ARGS="$CONFIG_ARGS --segment-max-memory ${SEGMENT_MAX_MEMORY}"
fi

BIN_ARGS="--mode $MODE \
$CONFIG_ARGS"

if [ "$MODE" != "generate-vm-vkey" ]; then
    BIN_ARGS="$BIN_ARGS \
--block-number $BLOCK_NUMBER \
--rpc-url $RPC_1 \
--cache-dir rpc-cache"
fi
export RUST_LOG="info,p3_=warn"

echo "Run command:"
echo "$BIN $BIN_ARGS"
if [ "$USE_PERF" = "true" ]; then
    # Set sampling frequency based on mode
    if [[ "$MODE" == "execute-host" || "$MODE" == "execute" || "$MODE" == "execute-metered" ]]; then
        PERF_FREQ=4000
    else
        PERF_FREQ=100
    fi

    echo "Running with perf profiling (freq=${PERF_FREQ})..."
    export OUTPUT_PATH="metrics.json"
    perf record -F $PERF_FREQ --call-graph=fp -g -o perf.data -- $BIN $BIN_ARGS

    echo "Converting perf.data with samply..."
    mkdir -p samply_profile
    samply import perf.data --presymbolicate --save-only --output samply_profile/profile.json.gz
    echo "Saved profile: samply_profile/profile.json.gz"

    FIREFOX_PROFILER_URL=$(python3 "$REPO_ROOT/scripts/upload_firefox_profile.py" samply_profile/profile.json.gz) || true

    if [ -n "$FIREFOX_PROFILER_URL" ]; then
        echo "Firefox Profiler URL: $FIREFOX_PROFILER_URL"
    else
        echo "Warning: failed to upload profile to Firefox Profiler"
    fi
elif [ "$USE_NSYS" = "true" ]; then
    NSYS_OUTPUT="reth.nsys-rep"
    NSYS_ARGS="--trace=cuda,nvtx,osrt --sample=cpu --cpuctxsw=process-tree --cuda-memory-usage=true --force-overwrite=true -o $NSYS_OUTPUT"
    if [ "$USE_NSYS_GPU_METRICS" = "true" ]; then
        NSYS_ARGS="$NSYS_ARGS --gpu-metrics-devices=all"
    fi

    echo "[sudo] Running with nsys profiling..."
    sudo env PATH="$PATH" HOME="$HOME" RUST_LOG="$RUST_LOG" \
         VPMM_PAGE_SIZE="${VPMM_PAGE_SIZE:-}" VPMM_PAGES="${VPMM_PAGES:-}" \
         LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" \
         nsys profile $NSYS_ARGS \
         $BIN $BIN_ARGS

    echo "=== CUDA GPU Kernel Summary ==="
    nsys stats --force-export=true --report cuda_gpu_kern_sum "$NSYS_OUTPUT"
    echo "=== CUDA Memory Time Summary ==="
    nsys stats --force-export=true --report cuda_gpu_mem_time_sum "$NSYS_OUTPUT"
    echo "=== CUDA Memory Size Summary ==="
    nsys stats --force-export=true --report cuda_gpu_mem_size_sum "$NSYS_OUTPUT"
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
