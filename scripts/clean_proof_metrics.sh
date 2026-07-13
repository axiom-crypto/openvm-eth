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

# openvm-prof's headline proof total is derived from total_proof_time_ms. That
# span legitimately covers the per-segment proving pipeline: preflight,
# trace generation, and STARK proving (plus small per-segment orchestration
# overhead). All of those are real proof costs and must stay in the total.
#
# The ONE contaminant is the lazy RVR AOT native compile. It fires once, on the
# first preflight of segment 0, so compile_preflight_time_ms is nested inside
# that segment's total_proof_time_ms. We remove exactly that, per (group,
# segment), and leave every other component of the total intact.
#
# We do NOT subtract compile_metered_time_ms: it belongs to the metered
# execution phase (it carries no segment label and, verified against captured
# runs, is not part of any total_proof span). Metered execution is already
# excluded from the proof headline below, so subtracting compile_metered from
# total_proof would double-remove it and push the total too low.
#
# When the harness pre-warms the AOT libraries (built untimed before the
# measured run), the timed metrics carry no compile_preflight span at all, so
# the subtraction is a no-op and the raw total already stands. The interpreter
# backend never emits compile_preflight, so its total is likewise unchanged.
#
# The raw, compile-inclusive total is preserved under
# pipeline_time_including_setup_ms as a diagnostic. Serial execution metrics are
# renamed so openvm-prof does not fold them into its headline proof total.
jq '
  def lbl($s; $k): ([$s.labels[]? | select(.[0] == $k) | .[1]][0] // "");
  def seg_key($s): (lbl($s; "group") + "\u001f" + lbl($s; "segment"));

  if (.gauge | any(.metric == "total_proof_time_ms")) then
    if (.gauge | any(.metric == "stark_prove_excluding_trace_time_ms") | not) then
      error("proof metrics contain total_proof_time_ms but no stark_prove_excluding_trace_time_ms")
    else
      .gauge as $gauges
      # Sum the one-time AOT preflight compile per (group, segment). Only
      # compile_preflight is nested inside total_proof; compile_metered has no
      # segment label and so matches no total_proof sample.
      | ($gauges
          | map(select(.metric == "compile_preflight_time_ms")
                | { key: seg_key(.), value: (.value | tonumber) })
          | reduce .[] as $c ({}; .[$c.key] += $c.value)
        ) as $compile_by_key
      | .gauge = (
          ($gauges | map(
            . as $sample
            | if .metric == "total_proof_time_ms" then
                (($compile_by_key[seg_key($sample)] // 0) as $compile
                 | .value = (((.value | tonumber) - $compile) | tostring))
              elif .metric == "execute_metered_time_ms" then
                .metric = "execute_metered_time_excluded_from_proof_ms"
              elif .metric == "execute_pure_time_ms" then
                .metric = "execute_pure_time_excluded_from_proof_ms"
              else
                .
              end
          ))
          # Preserve the raw compile-inclusive total as a diagnostic.
          + ($gauges | map(
              select(.metric == "total_proof_time_ms")
              | .metric = "pipeline_time_including_setup_ms"
          ))
        )
    end
  elif (.gauge | any(.metric == "stark_prove_excluding_trace_time_ms")) then
    .
  else
    .
  end
' "$input" > "$output"

clean_count=$(jq '[.gauge[] | select(.metric == "total_proof_time_ms")] | length' "$output")
clean_sum_ms=$(jq '[.gauge[] | select(.metric == "total_proof_time_ms") | (.value | tonumber)] | add // 0' "$output")
raw_sum_ms=$(jq '[.gauge[] | select(.metric == "pipeline_time_including_setup_ms") | (.value | tonumber)] | add // 0' "$output")
compile_sum_ms=$(jq '[.gauge[] | select(.metric == "compile_preflight_time_ms") | (.value | tonumber)] | add // 0' "$output")
echo "Clean proof metrics: count=${clean_count}, total_proof_sum_ms=${clean_sum_ms} (raw pipeline_incl_setup=${raw_sum_ms}, one-time compile_preflight removed=${compile_sum_ms})"
