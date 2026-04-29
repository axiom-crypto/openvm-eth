#!/bin/bash
#
# GPU Memory Monitoring Utilities
# This script provides functions for monitoring GPU memory usage via nvidia-smi.
# Source this file to use the functions.
#
# Usage:
#   source gpu_monitor.sh
#   start_gpu_monitor [log_file] [interval]
#   # ... run your workload ...
#   finalize_gpu_monitor
#   echo "Peak: $(mib_to_gb $GPU_PEAK_MEMORY) GB"
#
# Environment variables (set after finalize_gpu_monitor):
#   GPU_PEAK_MEMORY - Peak GPU memory usage in MiB
#

# Convert MiB to GB with 2 decimal places (1 GB = 1024 MiB)
mib_to_gb() {
    local mib="${1:-0}"
    awk "BEGIN { printf \"%.2f\", $mib / 1024 }"
}

GPU_LOG_FILE="${GPU_LOG_FILE:-gpu_memory_usage.csv}"
GPU_MONITOR_INTERVAL="${GPU_MONITOR_INTERVAL:-5}"
GPU_MONITOR_PID=""
GPU_PEAK_FILE=""
GPU_MONITOR_ACTIVE=false
GPU_PEAK_MEMORY=0

start_gpu_monitor() {
    local log_file="${1:-$GPU_LOG_FILE}"
    local interval="${2:-$GPU_MONITOR_INTERVAL}"

    if [ "$GPU_MONITOR_ACTIVE" = "true" ]; then
        return
    fi

    # Check if nvidia-smi is available
    if ! command -v nvidia-smi >/dev/null 2>&1 || ! nvidia-smi >/dev/null 2>&1; then
        echo "nvidia-smi not available; GPU memory monitoring disabled."
        return
    fi

    GPU_LOG_FILE="$log_file"
    GPU_MONITOR_INTERVAL="$interval"
    GPU_PEAK_FILE=$(mktemp)
    GPU_MONITOR_ACTIVE=true
    echo "timestamp,gpu_index,memory_used_mib" > "$GPU_LOG_FILE"
    echo 0 > "$GPU_PEAK_FILE"
    echo "Recording GPU memory usage to $GPU_LOG_FILE (interval: ${GPU_MONITOR_INTERVAL}s)."

    (
        set +e
        peak=0
        trap 'echo "$peak" > "'"$GPU_PEAK_FILE"'"; exit 0' TERM INT
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
        GPU_PEAK_MEMORY=0
        return
    fi

    if [ -n "$GPU_MONITOR_PID" ]; then
        kill "$GPU_MONITOR_PID" >/dev/null 2>&1 || true
        wait "$GPU_MONITOR_PID" 2>/dev/null || true
        GPU_MONITOR_PID=""
    fi

    GPU_PEAK_MEMORY="0"
    if [ -n "$GPU_PEAK_FILE" ] && [ -f "$GPU_PEAK_FILE" ]; then
        GPU_PEAK_MEMORY=$(cat "$GPU_PEAK_FILE")
        rm -f "$GPU_PEAK_FILE"
    fi

    echo "Peak GPU memory usage: $(mib_to_gb ${GPU_PEAK_MEMORY:-0}) GB (logged to $GPU_LOG_FILE)"
    GPU_MONITOR_ACTIVE=false
}
