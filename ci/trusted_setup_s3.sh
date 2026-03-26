#!/bin/bash
set -euo pipefail

# Downloads KZG BN254 SRS files needed for halo2 proving.
# Files are downloaded from the Axiom S3 bucket and placed in
# the default openvm params directory (~/.openvm/params/).
#
# Usage:
#   ./ci/trusted_setup_s3.sh [--params-dir <dir>] [--min-k <n>] [--max-k <n>]
#
# Options:
#   --params-dir <dir>  Directory to store SRS files (default: ~/.openvm/params/)
#   --min-k <n>         Minimum k value to download (default: 5)
#   --max-k <n>         Maximum k value to download (default: 24)

PARAMS_DIR="$HOME/.openvm/params"
MIN_K=5
MAX_K=24

while [[ $# -gt 0 ]]; do
    case $1 in
        --params-dir)
            PARAMS_DIR="$2"
            shift 2
            ;;
        --min-k)
            MIN_K="$2"
            shift 2
            ;;
        --max-k)
            MAX_K="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

mkdir -p "$PARAMS_DIR"

for k in $(seq "$MIN_K" "$MAX_K"); do
    FILE="kzg_bn254_${k}.srs"
    DEST="$PARAMS_DIR/$FILE"
    if [ -f "$DEST" ]; then
        echo "Already exists: $FILE"
    else
        echo "Downloading $FILE..."
        wget -q -O "$DEST" "https://axiom-crypto.s3.amazonaws.com/challenge_0085/$FILE"
    fi
done

echo "KZG params ready in $PARAMS_DIR"
