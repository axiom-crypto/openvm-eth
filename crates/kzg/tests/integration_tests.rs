use std::path::PathBuf;

use openvm_build::{GuestOptions, TargetFilter};
use openvm_kzg::{
    test_files::{
        ONLY_INVALID_KZG_PROOF_TESTS, ONLY_VALID_KZG_PROOF_TESTS, SINGLE_VALID_KZG_PROOF_TEST,
    },
    test_utils::{Input, Test},
    KzgInputs,
};
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig},
    CompiledExePure, ExecutableFormat, Sdk, StdIn,
};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_sdk::utils::setup_tracing;
use serde_yaml::from_str;

#[test]
fn test_single_valid_verify_kzg() {
    let (_, data) = SINGLE_VALID_KZG_PROOF_TEST[0];
    let sdk = create_sdk();
    let elf = build_guest(&sdk);
    let input = parse_inputs(data).expect("Invalid test inputs");
    sdk.app_prover(elf).unwrap().prove(stdin(&input)).unwrap();
}

#[test]
fn test_multiple_valid_verify_kzg() {
    let sdk = create_sdk();
    let elf = build_guest(&sdk);
    let compiled = sdk.compile(elf).unwrap();
    for (test_file, data) in ONLY_VALID_KZG_PROOF_TESTS {
        println!("Running test: {}", test_file);
        let input = parse_inputs(data).expect("Invalid test inputs");
        sdk.execute(&compiled, stdin(&input))
            .unwrap_or_else(|err| panic!("Test {} failed: {}", test_file, err));
    }
}

/// Proves every valid vector with a shared prover so keygen runs once.
#[ignore = "run via the run-kzg-proving CI label"]
#[test]
fn test_prove_multiple_valid_verify_kzg() {
    let sdk = create_sdk();
    let elf = build_guest(&sdk);
    let mut prover = sdk.app_prover(elf).unwrap();
    for (test_file, data) in ONLY_VALID_KZG_PROOF_TESTS {
        println!("Proving test: {}", test_file);
        let input = parse_inputs(data).expect("Invalid test inputs");
        prover.prove(stdin(&input)).unwrap();
    }
}

#[test]
fn test_single_invalid_verify_kzg() {
    let (test_file, data) = ONLY_INVALID_KZG_PROOF_TESTS[0];
    let sdk = create_sdk();
    let elf = build_guest(&sdk);
    let compiled = sdk.compile(elf).unwrap();
    assert_rejected(&sdk, &compiled, test_file, data);
}

#[test]
fn test_multiple_invalid_verify_kzg() {
    let sdk = create_sdk();
    let elf = build_guest(&sdk);
    let compiled = sdk.compile(elf).unwrap();
    for (test_file, data) in ONLY_INVALID_KZG_PROOF_TESTS {
        println!("Running test: {}", test_file);
        assert_rejected(&sdk, &compiled, test_file, data);
    }
}

/// Passes if the vector is rejected at input parsing or by the guest trapping.
fn assert_rejected(sdk: &Sdk, compiled: &CompiledExePure<'_>, test_file: &str, data: &str) {
    let Some(input) = parse_inputs(data) else {
        return;
    };
    let result = sdk.execute(compiled, stdin(&input));
    assert!(result.is_err(), "Test {} should have failed", test_file);
}

fn parse_inputs(data: &str) -> Option<KzgInputs> {
    let test: Test<Input<'_>> = from_str(data).unwrap();
    let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
        test.input.get_commitment(),
        test.input.get_z(),
        test.input.get_y(),
        test.input.get_proof(),
    ) else {
        return None;
    };
    Some(KzgInputs { commitment_bytes: commitment, z_bytes: z, y_bytes: y, proof_bytes: proof })
}

fn stdin(input: &KzgInputs) -> StdIn {
    let mut io = StdIn::default();
    io.write(input);
    io
}

fn create_sdk() -> Sdk {
    setup_tracing();
    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(include_str!("programs/verify_kzg/openvm.toml")).unwrap();
    Sdk::new(app_config, AggregationSystemParams::default()).unwrap()
}

fn build_guest(sdk: &Sdk) -> ExecutableFormat {
    let guest_opts = GuestOptions::default();
    let target_filter =
        Some(TargetFilter { name: "verify-kzg-program".to_string(), kind: "bin".to_string() });
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pkg_dir.push("tests");
    pkg_dir.push("programs");
    pkg_dir.push("verify_kzg");
    sdk.build(guest_opts, &pkg_dir, &target_filter, None).unwrap().into()
}
