//! Soundness reporting for the app + aggregation layers, computed from the app + aggregation
//! proving keys (loaded from disk if present, otherwise generated in memory) so the output
//! reflects this prover's exact production parameters. Two views are offered:
//! [`security_bits_report`] runs the stark-backend [`SoundnessCalculator`] and emits the computed
//! security bits as JSON, and [`SoundcalcConfig`] exports a
//! [`soundcalc`](https://github.com/ethereum/soundcalc)-compatible config for the external tool.

use openvm_sdk::SC;
use openvm_stark_sdk::openvm_stark_backend::{
    keygen::types::MultiStarkVerifyingKey, soundness::SoundnessCalculator, ProximityRegime,
};
use serde::Serialize;
use serde_json::json;

/// A named verifying key for one layer of the proof stack (e.g. `"app"`, `"leaf"`).
pub(crate) type Layer = (String, MultiStarkVerifyingKey<SC>);

/// Computes per-component security bits for each layer via the stark-backend
/// [`SoundnessCalculator`] and serializes them as JSON (`{"circuits": [{ "name", "security_bits":
/// {.., "total"} }]}`). `total` is the binding security level for the layer, so a CI gate is e.g.
/// `jq -e 'all(.circuits[]; .security_bits.total >= 100)'`.
pub(crate) fn security_bits_report(layers: &[Layer]) -> String {
    let circuits: Vec<_> = layers
        .iter()
        .map(|(name, vk)| {
            let s = SoundnessCalculator::calculate_from_vk(vk);
            json!({
                "name": name,
                "security_bits": {
                    "logup": s.logup_bits,
                    "gkr_sumcheck": s.gkr_sumcheck_bits,
                    "gkr_batching": s.gkr_batching_bits,
                    "zerocheck_sumcheck": s.zerocheck_sumcheck_bits,
                    "constraint_batching": s.constraint_batching_bits,
                    "stacked_reduction": s.stacked_reduction_bits,
                    "whir": s.whir_bits,
                    "total": s.total_bits,
                },
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({ "circuits": circuits }))
        .expect("soundness report serializes")
}

/// `soundcalc`-compatible config (see github.com/ethereum/soundcalc, `zkvms/openvm2`).
///
/// Serialize to TOML with `toml::to_string`.
#[derive(Serialize)]
pub(crate) struct SoundcalcConfig {
    zkevm: Zkevm,
    swirl: Swirl,
    circuits: Vec<Circuit>,
}

#[derive(Serialize)]
struct Zkevm {
    name: String,
    protocol_family: String,
    version: String,
    field: String,
    hash_size_bits: usize,
}

#[derive(Serialize)]
struct Swirl {
    logup_max_interaction_count: u32,
    logup_log_max_message_length: u32,
    logup_pow_bits: usize,
}

#[derive(Serialize)]
struct Circuit {
    name: String,
    l_skip: usize,
    n_stack: usize,
    w_stack: usize,
    log_blowup: usize,
    whir_folding_pow_bits: usize,
    whir_mu_pow_bits: usize,
    explicit_regime: String,
    /// List-decoding multiplicity bound, emitted only for the `"list"` regime (matching
    /// soundcalc's openvm2 loader, which reads `explicit_m` only when `explicit_regime ==
    /// "list"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    explicit_m: Option<usize>,
    whir_num_queries: Vec<usize>,
    constraint_degree: usize,
    max_constraints_per_air: usize,
    num_airs: usize,
    max_log_trace_height: usize,
    num_trace_columns: usize,
    max_interactions_per_air: usize,
}

impl SoundcalcConfig {
    /// Builds a soundcalc config with one `[[circuits]]` entry per layer.
    pub(crate) fn from_layers(version: String, layers: &[Layer]) -> Self {
        let circuits: Vec<Circuit> =
            layers.iter().map(|(name, vk)| Circuit::from_vk(name.clone(), vk)).collect();

        // The soundcalc schema has a single global `[swirl]` table; the LogUp parameters are
        // shared across layers, so take them from the first layer.
        let logup = &layers[0].1.inner.params.logup;

        Self {
            zkevm: Zkevm {
                name: "OpenVM2".to_string(),
                protocol_family: "SWIRL".to_string(),
                version,
                field: "BabyBear^4".to_string(),
                hash_size_bits: 256,
            },
            swirl: Swirl {
                logup_max_interaction_count: logup.max_interaction_count,
                logup_log_max_message_length: logup.log_max_message_length,
                logup_pow_bits: logup.pow_bits,
            },
            circuits,
        }
    }
}

impl Circuit {
    fn from_vk(name: String, vk: &MultiStarkVerifyingKey<SC>) -> Self {
        let params = &vk.inner.params;

        let mut max_constraints_per_air = 0;
        let mut max_interactions_per_air = 0;
        let mut num_trace_columns = 0;
        for air_vk in &vk.inner.per_air {
            max_constraints_per_air = max_constraints_per_air
                .max(air_vk.symbolic_constraints.constraints.constraint_idx.len());
            max_interactions_per_air =
                max_interactions_per_air.max(air_vk.symbolic_constraints.interactions.len());
            num_trace_columns += air_vk.params.width.total_width();
        }

        let (explicit_regime, explicit_m) = match params.whir.proximity.initial_round() {
            ProximityRegime::UniqueDecoding => ("unique".to_string(), None),
            ProximityRegime::ListDecoding { m } => ("list".to_string(), Some(m)),
        };

        Self {
            name,
            l_skip: params.l_skip,
            n_stack: params.n_stack,
            w_stack: params.w_stack,
            log_blowup: params.log_blowup,
            whir_folding_pow_bits: params.whir.folding_pow_bits,
            whir_mu_pow_bits: params.whir.mu_pow_bits,
            explicit_regime,
            explicit_m,
            whir_num_queries: params.whir.rounds.iter().map(|r| r.num_queries).collect(),
            constraint_degree: params.max_constraint_degree,
            max_constraints_per_air,
            num_airs: vk.inner.per_air.len(),
            max_log_trace_height: params.log_stacked_height(),
            num_trace_columns,
            max_interactions_per_air,
        }
    }
}
