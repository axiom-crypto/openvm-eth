#!/usr/bin/env bash
set -euo pipefail

S3_BUCKET="${S3_BUCKET:-cloud-proving-staging-data}"
S3_PREFIX="${S3_PREFIX:-proofs/testing}"

# Wrapper around the OpenVM benchmark binary to allow post-processing
# after proving completes. All arguments are forwarded to the binary.

BIN_PATH="${OVM_BIN:-/usr/local/bin/openvm-reth-benchmark}"
JOBS_DIR="${JOBS_DIR:-/app/jobs}"
MODE="${MODE:-prove-stark}"
VPMM_PAGE_SIZE=$((4 << 20))
VPMM_PAGES="${VPMM_PAGES:-$((16 << 8))}"

if [[ $# -lt 1 ]]; then
  echo "[prove_block.sh] Usage: $0 <proof_uuid>" >&2
  exit 2
fi

PROOF_UUID="$1"

if [[ ! -f "$BIN_PATH" ]]; then
  echo "[prove_block.sh] Error: Binary not found at $BIN_PATH" >&2
  exit 127
fi

job_dir="${JOBS_DIR}/${PROOF_UUID}"
mkdir -p "$job_dir"

echo "[prove_block.sh] Starting proof at $(date -Is) with BIN=$BIN_PATH" >&2
echo "[prove_block.sh] Job dir: $job_dir" >&2
echo "[prove_block.sh] Downloading input from s3://${S3_BUCKET}/${S3_PREFIX}/${PROOF_UUID}" >&2

# Try to download as a prefix first; if that fails, try single object copy
set +e
s5cmd cp "s3://${S3_BUCKET}/${S3_PREFIX}/${PROOF_UUID}/input.json" "$job_dir/"
rc=$?
if [[ $rc -ne 0 ]]; then
    echo "[prove_block.sh] Failed to download input from S3 (rc=$rc)" >&2
    exit $rc
fi

set -e

# Determine input path
INPUT_PATH="$job_dir/input.json"

if [[ -z "$INPUT_PATH" ]]; then
  echo "[prove_block.sh] Could not determine input file in $job_dir" >&2
  exit 1
fi
echo "[prove_block.sh] Using input: $INPUT_PATH" >&2

start_ts_ms=$(date +%s%3N)
PROOF_JSON="$job_dir/proof.json"

OUTPUT_PATH="$job_dir/metrics.json"

args=(
  --mode "$MODE" \
  --block-number 1234 \
  --input-path "$INPUT_PATH" \
  --output-dir "$job_dir" \
  --app-pk-path /app/app_pk \
  --agg-pk-path /app/agg_pk
)

if [[ -n "${APP_LOG_BLOWUP:-}" ]]; then
  args+=(--app-log-blowup "$APP_LOG_BLOWUP")
fi
if [[ -n "${APP_L_SKIP:-}" ]]; then
  args+=(--app-l-skip "$APP_L_SKIP")
fi
if [[ -n "${LEAF_LOG_BLOWUP:-}" ]]; then
  args+=(--leaf-log-blowup "$LEAF_LOG_BLOWUP")
fi
if [[ -n "${INTERNAL_LOG_BLOWUP:-}" ]]; then
  args+=(--internal-log-blowup "$INTERNAL_LOG_BLOWUP")
fi
if [[ -n "${ROOT_LOG_BLOWUP:-}" ]]; then
  args+=(--root-log-blowup "$ROOT_LOG_BLOWUP")
fi
if [[ -n "${NUM_CHILDREN_LEAF:-}" ]]; then
  args+=(--num-children-leaf "$NUM_CHILDREN_LEAF")
fi
if [[ -n "${NUM_CHILDREN_INTERNAL:-}" ]]; then
  args+=(--num-children-internal "$NUM_CHILDREN_INTERNAL")
fi
if [[ -n "${MAX_SEGMENT_LENGTH:-}" ]]; then
  args+=(--max-segment-length "$MAX_SEGMENT_LENGTH")
fi
if [[ -n "${SEGMENT_MAX_MEMORY:-}" ]]; then
  args+=(--segment-max-memory "$SEGMENT_MAX_MEMORY")
fi

"$BIN_PATH" "${args[@]}"
status=$?

end_ts_ms=$(date +%s%3N)
duration_ms=$(( end_ts_ms - start_ts_ms ))
echo "$duration_ms" > "$job_dir/latency_ms.txt"

# Post-processing hook: customize as needed
echo "[prove_block.sh] Proof finished with status=$status in ${duration_ms}ms at $(date -Is)" >&2

# Upload proof.json to S3 (best-effort)
if [[ -f "$PROOF_JSON" ]]; then
  set +e
  s5cmd cp "$PROOF_JSON" "s3://${S3_BUCKET}/${S3_PREFIX}/${PROOF_UUID}/proof.json"
  upload_rc=$?
  if [[ $upload_rc -ne 0 ]]; then
    echo "[prove_block.sh] Warning: failed to upload proof.json to S3 (rc=$upload_rc)" >&2
  fi
  set -e
else
  echo "[prove_block.sh] Warning: proof.json not found at $PROOF_JSON" >&2
fi

if [[ -f "$OUTPUT_PATH" ]]; then
  s5cmd cp "$OUTPUT_PATH" "s3://${S3_BUCKET}/${S3_PREFIX}/${PROOF_UUID}/metrics.json"
  upload_rc=$?
  if [[ $upload_rc -ne 0 ]]; then
    echo "[prove_block.sh] Warning: failed to upload metrics.json to S3 (rc=$upload_rc)" >&2
  fi
else
  echo "[prove_block.sh] Warning: metrics.json not found at $OUTPUT_PATH" >&2
fi

exit $status
