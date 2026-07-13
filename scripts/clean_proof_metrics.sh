#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <raw-metrics.json> <report-metrics.json>" >&2
  exit 2
fi

input=$1
output=$2

if [[ "$input" == "$output" ]]; then
  echo "input and output paths must differ" >&2
  exit 2
fi

# openvm-prof's headline proof total is derived from total_proof_time_ms. The
# broad total_proof span can include lazy RVR native compilation, preflight,
# and trace generation. Preserve those samples under a diagnostic name, then
# use the backend's trace-exclusive STARK proving span for the proof headline.
# The backend emits this span after either interpreter or RVR preflight. Serial
# execution metrics are renamed as well because openvm-prof otherwise adds
# them to its headline proof total.
jq '
  def group_name($sample):
    ([$sample.labels[]? | select(.[0] == "group") | .[1]][0] // "");

  if (.gauge | any(.metric == "stark_prove_excluding_trace_time_ms")) then
    .gauge as $gauges
    | ($gauges
      | map(select(.metric == "stark_prove_excluding_trace_time_ms") | group_name(.))
      | unique
    ) as $clean_groups
    | .gauge = (
        ($gauges | map(
          . as $sample
          | if .metric == "total_proof_time_ms"
            and ($clean_groups | index(group_name($sample))) != null then
            .metric = "pipeline_time_including_setup_ms"
          elif .metric == "execute_metered_time_ms" then
            .metric = "execute_metered_time_excluded_from_proof_ms"
          elif .metric == "execute_pure_time_ms" then
            .metric = "execute_pure_time_excluded_from_proof_ms"
          else
            .
          end
        ))
        + ($gauges | map(
          select(.metric == "stark_prove_excluding_trace_time_ms")
          | .metric = "total_proof_time_ms"
        ))
      )
  elif (.gauge | any(.metric == "total_proof_time_ms")) then
    error("proof metrics contain total_proof_time_ms but no stark_prove_excluding_trace_time_ms")
  else
    .
  end
' "$input" > "$output"

clean_count=$(jq '[.gauge[] | select(.metric == "total_proof_time_ms")] | length' "$output")
clean_sum_ms=$(jq '[.gauge[] | select(.metric == "total_proof_time_ms") | (.value | tonumber)] | add // 0' "$output")
echo "Clean proof metrics: count=${clean_count}, sum_ms=${clean_sum_ms}"
