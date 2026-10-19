use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, io,
    path::{Path, PathBuf},
};

use openvm_revm_crypto::install_openvm_crypto;
use rayon::prelude::*;
use serde::Deserialize;
use stateless_validator_reth::guest::run_stateless_guest;
use thiserror::Error;

const EXPECTED_FIXTURE_COUNT: usize = 33_614;

/// Fixtures whose upstream results differ from the execution specs, independent of OpenVM's crypto.
///
/// - EIP-7928: alloy-evm runs the post-execution system calls before it credits withdrawals, and
///   revm's block access list builder records a change when a value returns to its start-of-index
///   value. The stateless validator lists the same fixtures as known failures.
/// - EIP-8037: revm 43.0.2 moved the system call state-gas margin into the state gas reservoir,
///   which these fixtures do not expect.
const KNOWN_DIVERGENCES: &[&str] = &[
    "tests/amsterdam/eip7928_block_level_access_lists/test_block_access_lists_cross_index.py::test_bal_post_execution_calls_net_storage_at_last_index[fork_Amsterdam-blockchain_test]#block0",
    "tests/amsterdam/eip7928_block_level_access_lists/test_block_access_lists_cross_index.py::test_bal_withdrawals_and_dequeues_net_balance_at_last_index[fork_Amsterdam-blockchain_test-forward_all]#block0",
    "tests/amsterdam/eip7928_block_level_access_lists/test_block_access_lists_cross_index.py::test_bal_withdrawals_and_dequeues_net_balance_at_last_index[fork_Amsterdam-blockchain_test-forward_half]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_execution_boundary[fork_Amsterdam-blockchain_test-beacon-one_over]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_execution_boundary[fork_Amsterdam-blockchain_test-history-one_over]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_execution_grant[fork_Amsterdam-blockchain_test-beacon]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_execution_grant[fork_Amsterdam-blockchain_test-builder_deposit]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_execution_grant[fork_Amsterdam-blockchain_test-builder_exit]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_execution_grant[fork_Amsterdam-blockchain_test-consolidations]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_execution_grant[fork_Amsterdam-blockchain_test-history]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_execution_grant[fork_Amsterdam-blockchain_test-withdrawals]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_False-beacon]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_False-builder_deposit]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_False-builder_exit]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_False-consolidations]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_False-history]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_False-withdrawals]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_True-beacon]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_True-builder_deposit]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_True-builder_exit]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_True-consolidations]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_True-history]#block0",
    "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_state_gas_system_calls.py::test_system_call_reservoir_boundary[fork_Amsterdam-blockchain_test-allow_spill_True-withdrawals]#block0",
];

#[derive(Debug)]
struct Fixture {
    name: String,
    input: Vec<u8>,
    expected_output: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    blocks: Vec<TestBlock>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestBlock {
    stateless_input_bytes: Option<String>,
    stateless_output_bytes: Option<String>,
}

#[derive(Debug, Error)]
enum FixtureError {
    #[error("EEST_FIXTURES_DIR is not set")]
    MissingFixtureRoot,
    #[error("failed to access fixture path {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse fixture file {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("fixture {fixture} in {path} contains invalid hex: {source}")]
    Hex {
        path: PathBuf,
        fixture: String,
        #[source]
        source: hex::FromHexError,
    },
}

#[test]
#[ignore = "requires tests-zkevm@v21.0.1 fixtures"]
fn execution_spec_tests() -> Result<(), FixtureError> {
    let fixture_root = env::var_os("EEST_FIXTURES_DIR")
        .map(PathBuf::from)
        .ok_or(FixtureError::MissingFixtureRoot)?;
    let fixtures = load_fixture_suite(&fixture_root)?;
    assert_eq!(
        fixtures.len(),
        EXPECTED_FIXTURE_COUNT,
        "fixture count changed; verify that the configured release was fully extracted"
    );

    let crypto_installed =
        install_openvm_crypto().expect("failed to install OpenVM crypto providers");
    assert!(crypto_installed, "another revm crypto provider was installed first");

    let failures = fixtures
        .par_iter()
        .filter_map(|fixture| {
            let output = run_stateless_guest(&fixture.input);
            (output != fixture.expected_output).then(|| fixture.name.as_str())
        })
        .collect::<BTreeSet<_>>();
    let known_divergences = KNOWN_DIVERGENCES.iter().copied().collect::<BTreeSet<_>>();

    let unexpected = failures.difference(&known_divergences).copied().collect::<Vec<_>>();
    let resolved = known_divergences.difference(&failures).copied().collect::<Vec<_>>();
    assert!(
        unexpected.is_empty() && resolved.is_empty(),
        "execution-spec results changed\nunexpected failures:\n{}\nresolved known divergences:\n{}",
        format_names(&unexpected),
        format_names(&resolved),
    );

    Ok(())
}

fn load_fixture_suite(root: &Path) -> Result<Vec<Fixture>, FixtureError> {
    let fixture_files = find_fixture_files(root)?;
    let fixture_batches = fixture_files
        .par_iter()
        .map(|path| load_fixture_file(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut fixtures = fixture_batches.into_iter().flatten().collect::<Vec<_>>();
    fixtures.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(fixtures)
}

fn find_fixture_files(root: &Path) -> Result<Vec<PathBuf>, FixtureError> {
    let mut directories = vec![root.to_path_buf()];
    let mut fixture_files = Vec::new();

    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|source| FixtureError::Io { path: directory.clone(), source })?;
        for entry in entries {
            let entry =
                entry.map_err(|source| FixtureError::Io { path: directory.clone(), source })?;
            let file_type = entry
                .file_type()
                .map_err(|source| FixtureError::Io { path: entry.path(), source })?;
            if file_type.is_dir() {
                directories.push(entry.path());
            } else if entry.path().extension().is_some_and(|extension| extension == "json") {
                fixture_files.push(entry.path());
            }
        }
    }

    fixture_files.sort();
    Ok(fixture_files)
}

fn load_fixture_file(path: &Path) -> Result<Vec<Fixture>, FixtureError> {
    let bytes =
        fs::read(path).map_err(|source| FixtureError::Io { path: path.to_path_buf(), source })?;
    let test_cases: BTreeMap<String, TestCase> = serde_json::from_slice(&bytes)
        .map_err(|source| FixtureError::Json { path: path.to_path_buf(), source })?;

    test_cases
        .into_iter()
        .flat_map(|(test_name, test_case)| {
            test_case.blocks.into_iter().enumerate().filter_map(move |(block_index, block)| {
                block
                    .stateless_input_bytes
                    .zip(block.stateless_output_bytes)
                    .filter(|(input, _)| !input.is_empty())
                    .map(|(input, expected_output)| {
                        let name = format!("{test_name}#block{block_index}");
                        let input = decode_fixture_hex(path, &name, &input)?;
                        let expected_output = decode_fixture_hex(path, &name, &expected_output)?;
                        Ok(Fixture { name, input, expected_output })
                    })
            })
        })
        .collect()
}

fn decode_fixture_hex(path: &Path, fixture: &str, value: &str) -> Result<Vec<u8>, FixtureError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|source| FixtureError::Hex {
        path: path.to_path_buf(),
        fixture: fixture.to_string(),
        source,
    })
}

fn format_names(names: &[&str]) -> String {
    if names.is_empty() {
        return "  (none)".to_string();
    }
    names.iter().map(|name| format!("  - {name}")).collect::<Vec<_>>().join("\n")
}
