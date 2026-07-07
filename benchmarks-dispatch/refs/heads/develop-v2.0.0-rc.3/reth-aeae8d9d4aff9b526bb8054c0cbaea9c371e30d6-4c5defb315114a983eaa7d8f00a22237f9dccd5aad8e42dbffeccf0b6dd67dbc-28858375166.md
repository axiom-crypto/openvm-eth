| Summary | Proof Time (s) | Parallel Proof Time (s) | Parallel Proof Time (16 provers) (s) |
|:---|---:|---:|---:|
| Total |  93.68 |  5.75 |  10.01 |
| app_proof |  85.53 |  4.87 |  8.87 |
| leaf |  5.91 |  0.28 |  0.55 |
| internal_for_leaf |  1.57 |  0.20 |  0.20 |
| internal_recursive.0 |  0.42 |  0.15 |  0.15 |
| internal_recursive.1 |  0.15 |  0.15 |  0.15 |
| internal_recursive.2 |  0.09 |  0.09 |  0.09 |


| app_proof |||||
|:---|---:|---:|---:|---:|
|metric|avg|sum|max|min|
| `total_proof_time_ms ` |  913.74 |  83,150 |  2,484 |  374 |
| `execute_metered_time_ms` |  2,384 | -          | -          | -          |
| `execute_metered_insns` |  854,598,359 | -          | -          | -          |
| `execute_metered_insn_mi/s` |  358.42 | -          |  358.42 |  358.42 |
| `execute_preflight_insns` |  9,391,190.76 |  854,598,359 |  14,650,000 |  223,000 |
| `execute_preflight_time_ms` |  251.03 |  22,844 |  414 |  35 |
| `execute_preflight_insn_mi/s` |  39.40 | -          |  47.94 |  15.55 |
| `trace_gen_time_ms   ` |  97.96 |  8,914 |  1,352 |  23 |
| `memory_finalize_time_ms` |  6.30 |  573 |  21 |  0 |
| __Prover__ |||||
| `stark_prove_excluding_trace_time_ms` |  537.22 |  48,887 |  708 |  265 |
| `prover.main_trace_commit_time_ms` |  116.32 |  10,585 |  153 |  77 |
| `prover.rap_constraints_time_ms` |  287.55 |  26,167 |  448 |  96 |
| `prover.openings_time_ms` |  132.23 |  12,033 |  168 |  90 |
| `prover.rap_constraints.logup_gkr_time_ms` |  126.79 |  11,538 |  267 |  32 |
| `prover.rap_constraints.round0_time_ms` |  111.01 |  10,102 |  228 |  36 |
| `prover.rap_constraints.mle_rounds_time_ms` |  48.71 |  4,433 |  81 |  27 |
| `prover.openings.stacked_reduction_time_ms` |  30.45 |  2,771 |  41 |  17 |
| `prover.openings.stacked_reduction.round0_time_ms` |  16.58 |  1,509 |  23 |  9 |
| `prover.openings.stacked_reduction.mle_rounds_time_ms` |  13.27 |  1,208 |  18 |  8 |
| `prover.openings.whir_time_ms` |  101.31 |  9,219 |  126 |  72 |

| leaf |||||
|:---|---:|---:|---:|---:|
|metric|avg|sum|max|min|
| `total_proof_time_ms ` |  257.09 |  5,913 |  282 |  230 |
| `execute_preflight_time_ms` |  6 |  138 |  12 |  1 |
| `trace_gen_time_ms   ` |  57.04 |  1,312 |  73 |  39 |
| `generate_blob_total_time_ms` |  2.91 |  67 |  3 |  2 |
| __Prover__ |||||
| `stark_prove_excluding_trace_time_ms` |  199.65 |  4,592 |  209 |  190 |
| `prover.main_trace_commit_time_ms` |  45.70 |  1,051 |  49 |  42 |
| `prover.rap_constraints_time_ms` |  105.83 |  2,434 |  109 |  102 |
| `prover.openings_time_ms` |  47.09 |  1,083 |  49 |  44 |
| `prover.rap_constraints.logup_gkr_time_ms` |  34.83 |  801 |  35 |  34 |
| `prover.rap_constraints.round0_time_ms` |  39.57 |  910 |  41 |  37 |
| `prover.rap_constraints.mle_rounds_time_ms` |  30.30 |  697 |  31 |  29 |
| `prover.openings.stacked_reduction_time_ms` |  11.17 |  257 |  12 |  11 |
| `prover.openings.stacked_reduction.round0_time_ms` |  4 |  92 |  4 |  4 |
| `prover.openings.stacked_reduction.mle_rounds_time_ms` |  7 |  161 |  7 |  7 |
| `prover.openings.whir_time_ms` |  35.26 |  811 |  37 |  33 |

| internal_for_leaf |||||
|:---|---:|---:|---:|---:|
|metric|avg|sum|max|min|
| `total_proof_time_ms ` |  195.88 |  1,567 |  204 |  184 |
| `execute_preflight_time_ms` |  2 |  16 |  2 |  2 |
| `trace_gen_time_ms   ` |  31.88 |  255 |  34 |  23 |
| `generate_blob_total_time_ms` |  1.88 |  15 |  2 |  1 |
| __Prover__ |||||
| `stark_prove_excluding_trace_time_ms` |  163.50 |  1,308 |  171 |  161 |
| `prover.main_trace_commit_time_ms` |  41.38 |  331 |  45 |  40 |
| `prover.rap_constraints_time_ms` |  78.38 |  627 |  81 |  77 |
| `prover.openings_time_ms` |  42.50 |  340 |  44 |  41 |
| `prover.rap_constraints.logup_gkr_time_ms` |  14.25 |  114 |  15 |  14 |
| `prover.rap_constraints.round0_time_ms` |  26 |  208 |  27 |  25 |
| `prover.rap_constraints.mle_rounds_time_ms` |  37.13 |  297 |  38 |  37 |
| `prover.openings.stacked_reduction_time_ms` |  10 |  80 |  10 |  10 |
| `prover.openings.stacked_reduction.round0_time_ms` |  2 |  16 |  2 |  2 |
| `prover.openings.stacked_reduction.mle_rounds_time_ms` |  7 |  56 |  7 |  7 |
| `prover.openings.whir_time_ms` |  32.25 |  258 |  34 |  30 |

| internal_recursive.0 |||||
|:---|---:|---:|---:|---:|
|metric|avg|sum|max|min|
| `total_proof_time_ms ` |  141 |  423 |  153 |  119 |
| `execute_preflight_time_ms` |  2 |  6 |  2 |  2 |
| `trace_gen_time_ms   ` |  19.67 |  59 |  22 |  15 |
| `generate_blob_total_time_ms` |  1.67 |  5 |  2 |  1 |
| __Prover__ |||||
| `stark_prove_excluding_trace_time_ms` |  121 |  363 |  131 |  103 |
| `prover.main_trace_commit_time_ms` |  26 |  78 |  30 |  18 |
| `prover.rap_constraints_time_ms` |  61.67 |  185 |  64 |  58 |
| `prover.openings_time_ms` |  32 |  96 |  36 |  26 |
| `prover.rap_constraints.logup_gkr_time_ms` |  11.67 |  35 |  12 |  11 |
| `prover.rap_constraints.round0_time_ms` |  21.67 |  65 |  22 |  21 |
| `prover.rap_constraints.mle_rounds_time_ms` |  27.67 |  83 |  29 |  25 |
| `prover.openings.stacked_reduction_time_ms` |  8.33 |  25 |  9 |  7 |
| `prover.openings.stacked_reduction.round0_time_ms` |  1.67 |  5 |  2 |  1 |
| `prover.openings.stacked_reduction.mle_rounds_time_ms` |  6 |  18 |  6 |  6 |
| `prover.openings.whir_time_ms` |  23.33 |  70 |  27 |  18 |

| internal_recursive.1 |||||
|:---|---:|---:|---:|---:|
|metric|avg|sum|max|min|
| `total_proof_time_ms ` |  147 |  147 |  147 |  147 |
| `execute_preflight_time_ms` |  2 |  2 |  2 |  2 |
| `trace_gen_time_ms   ` |  17 |  17 |  17 |  17 |
| `generate_blob_total_time_ms` |  1 |  1 |  1 |  1 |
| __Prover__ |||||
| `stark_prove_excluding_trace_time_ms` |  129 |  129 |  129 |  129 |
| `prover.main_trace_commit_time_ms` |  30 |  30 |  30 |  30 |
| `prover.rap_constraints_time_ms` |  63 |  63 |  63 |  63 |
| `prover.openings_time_ms` |  35 |  35 |  35 |  35 |
| `prover.rap_constraints.logup_gkr_time_ms` |  11 |  11 |  11 |  11 |
| `prover.rap_constraints.round0_time_ms` |  22 |  22 |  22 |  22 |
| `prover.rap_constraints.mle_rounds_time_ms` |  29 |  29 |  29 |  29 |
| `prover.openings.stacked_reduction_time_ms` |  9 |  9 |  9 |  9 |
| `prover.openings.stacked_reduction.round0_time_ms` |  2 |  2 |  2 |  2 |
| `prover.openings.stacked_reduction.mle_rounds_time_ms` |  6 |  6 |  6 |  6 |
| `prover.openings.whir_time_ms` |  26 |  26 |  26 |  26 |

| internal_recursive.2 |||||
|:---|---:|---:|---:|---:|
|metric|avg|sum|max|min|
| `total_proof_time_ms ` |  94 |  94 |  94 |  94 |
| `execute_preflight_time_ms` |  2 |  2 |  2 |  2 |
| `trace_gen_time_ms   ` |  10 |  10 |  10 |  10 |
| `generate_blob_total_time_ms` |  0 |  0 |  0 |  0 |
| __Prover__ |||||
| `stark_prove_excluding_trace_time_ms` |  83 |  83 |  83 |  83 |
| `prover.main_trace_commit_time_ms` |  10 |  10 |  10 |  10 |
| `prover.rap_constraints_time_ms` |  51 |  51 |  51 |  51 |
| `prover.openings_time_ms` |  21 |  21 |  21 |  21 |
| `prover.rap_constraints.logup_gkr_time_ms` |  10 |  10 |  10 |  10 |
| `prover.rap_constraints.round0_time_ms` |  20 |  20 |  20 |  20 |
| `prover.rap_constraints.mle_rounds_time_ms` |  21 |  21 |  21 |  21 |
| `prover.openings.stacked_reduction_time_ms` |  6 |  6 |  6 |  6 |
| `prover.openings.stacked_reduction.round0_time_ms` |  1 |  1 |  1 |  1 |
| `prover.openings.stacked_reduction.mle_rounds_time_ms` |  5 |  5 |  5 |  5 |
| `prover.openings.whir_time_ms` |  14 |  14 |  14 |  14 |



## GPU Memory Usage

![GPU Memory Usage](https://axiom-public-data-sandbox-us-east-1.s3.us-east-1.amazonaws.com/benchmark/github/charts/aeae8d9d4aff9b526bb8054c0cbaea9c371e30d6/reth-aeae8d9d4aff9b526bb8054c0cbaea9c371e30d6-4c5defb315114a983eaa7d8f00a22237f9dccd5aad8e42dbffeccf0b6dd67dbc-28858375166.memory.svg)

| Module | Max (GB) | Max At |
| --- | ---: | --- |
| frac_sumcheck.gkr_rounds | 14.49 | app_proof.prover.61 |
| prover.batch_constraints.before_round0 | 14.49 | app_proof.prover.61 |
| prover.gkr_input_evals | 13.58 | app_proof.prover.61 |
| frac_sumcheck.segment_tree | 13.58 | app_proof.prover.61 |
| prover.stacked_commit | 12.42 | app_proof.prover.32 |
| prover.batch_constraints.fold_ple_evals | 9.72 | app_proof.prover.32 |
| prover.batch_constraints.round0 | 9.72 | app_proof.prover.32 |
| prover.rap_constraints | 9.72 | app_proof.prover.32 |
| prover.prove_whir_opening | 8.95 | app_proof.prover.32 |
| prover.merkle_tree | 8.95 | app_proof.prover.32 |
| prover.openings | 8.95 | app_proof.prover.32 |
| prover.rs_code_matrix | 8.95 | app_proof.prover.32 |
| generate mem proving ctxs | 5.20 | app_proof.1 |
| set initial memory | 4.87 | app_proof.4 |
| prover.before_gkr_input_evals | 4.48 | app_proof.prover.32 |
| tracegen.exp_bits_len | 1.06 | leaf.15 |
| tracegen.pow_checker | 1.06 | leaf.15 |
| tracegen.whir_final_poly_query_eval | 1.06 | leaf.15 |
| tracegen.whir_folding | 0.92 | leaf.15 |
| tracegen.whir_non_initial_opened_values | 0.91 | leaf.15 |
| tracegen.whir_initial_opened_values | 0.91 | leaf.15 |
| tracegen.public_values | 0.86 | leaf.15 |
| tracegen.range_checker | 0.86 | leaf.15 |
| tracegen.proof_shape | 0.86 | leaf.15 |

Commit: https://github.com/axiom-crypto/openvm-eth/commit/aeae8d9d4aff9b526bb8054c0cbaea9c371e30d6

Instance Type: g7e.2xlarge

Memory Allocator: jemalloc

[Benchmark Workflow](https://github.com/axiom-crypto/openvm-eth/actions/runs/28858375166)

**Peak GPU Memory (nvidia-smi):** 15.87 GB
