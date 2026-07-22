#!/bin/bash
set -euo pipefail

source .env
# Usage: ./generate-inputs-parallel.sh [--range START END] [--list BLOCK1,BLOCK2,...]
# Examples:
#   ./generate-inputs-parallel.sh --range 23000000 23000999
#   ./generate-inputs-parallel.sh --list 23009666,23009672,23002575

if [[ ${#RPC_URLS[@]} -eq 0 ]]; then
    echo "Error: RPC_URLS is empty. Please input your RPC URLs."
    exit 1
fi

# Parse arguments
MODE=""
BLOCKS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --range)
            MODE="range"
            RANGE_START="$2"
            RANGE_END="$3"
            shift 3
            ;;
        --list)
            MODE="list"
            IFS=',' read -ra BLOCKS <<< "$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--range START END] [--list BLOCK1,BLOCK2,...]"
            exit 1
            ;;
    esac
done

# Generate block list based on mode
if [[ "$MODE" == "range" ]]; then
    echo "Generating blocks from $RANGE_START to $RANGE_END..."
    for ((i=RANGE_START; i<=RANGE_END; i++)); do
        BLOCKS+=("$i")
    done
elif [[ "$MODE" == "list" ]]; then
    echo "Using provided block list (${#BLOCKS[@]} blocks)"
else
    echo "Error: Must specify either --range or --list"
    echo "Usage: $0 [--range START END] [--list BLOCK1,BLOCK2,...]"
    exit 1
fi

cd bin/reth-benchmark
# The binary has a static include_bytes! but doesn't really need this ELF for proof input generation:
mkdir -p elf
touch elf/openvm-stateless-guest
cargo build --bin openvm-reth-benchmark --release
cd ../..

BIN_PATH="$(pwd)/target/release/openvm-reth-benchmark"
# cur dir is openvm-reth-benchmark

OUTPUT_DIR="$(pwd)/inputs"
CACHE_DIR="$(pwd)/rpc-cache"
CONCURRENCY="${CONCURRENCY:-6}"  # Run 6 jobs in parallel (2 per RPC node)

# Create output directory
mkdir -p "$OUTPUT_DIR"
mkdir -p "$CACHE_DIR"

# Counter for round-robin RPC selection
rpc_index=0

# Function to generate input for a single block
generate_input() {
    local block=$1
    local rpc_url=$2
    local output_file="$OUTPUT_DIR/${block}.json"
    local log_file="$OUTPUT_DIR/${block}.log"

    # Skip if already exists and is valid JSON
    if [[ -f "$output_file" ]]; then
        if jq empty "$output_file" 2>/dev/null; then
            echo "✓ Block $block already exists, skipping"
            return 0
        else
            echo "⚠️  Block $block exists but is invalid, regenerating..."
            rm -f "$output_file"
        fi
    fi

    echo "🧮 Generating input for block $block using ${rpc_url:0:50}..."
    local start=$(date +%s)

    # Run the command (ignore exit code, check output instead)
    "$BIN_PATH" \
        --block-number "$block" \
        --mode make-input \
        --rpc-url "$rpc_url" \
        --cache-dir "$CACHE_DIR" \
        --generated-input-path "$output_file" > "$log_file" 2>&1 || true

    # Check if output file exists and is valid
    if [[ -f "$output_file" ]] && jq empty "$output_file" 2>/dev/null; then
        local end=$(date +%s)
        local duration=$((end - start))
        local size=$(du -h "$output_file" | cut -f1)
        echo "✅ Block $block done in ${duration}s (${size})"
        rm -f "$log_file"
    else
        echo "❌ Failed block $block - see $log_file for details"
        rm -f "$output_file"  # Clean up potentially incomplete file
        return 1
    fi
}

export -f generate_input
export BIN_PATH CACHE_DIR OUTPUT_DIR

# Build array of arguments for parallel execution
args=()
for block in "${BLOCKS[@]}"; do
    # Round-robin RPC selection
    rpc_url="${RPC_URLS[$rpc_index]}"
    rpc_index=$(( (rpc_index + 1) % ${#RPC_URLS[@]} ))

    args+=("$block" "$rpc_url")
done

# Run in parallel using xargs
echo "🚀 Starting generation of ${#BLOCKS[@]} blocks with concurrency=$CONCURRENCY"
echo ""
overall_start=$(date +%s)

printf "%s\n" "${args[@]}" | xargs -n 2 -P "$CONCURRENCY" bash -c 'generate_input "$@"' _

overall_end=$(date +%s)
overall_duration=$((overall_end - overall_start))

echo ""
echo "✅ All done in ${overall_duration}s!"
echo "📊 Total files: $(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l)"
echo "⏱️  Average: $((overall_duration / ${#BLOCKS[@]}))s per block"
