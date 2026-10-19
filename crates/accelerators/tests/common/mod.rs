//! Helpers shared by the accelerator tests.

use std::process::Command;

/// Selects the case that a child process runs (see [`assert_null_pointer_panic`]).
const CASE_ENV: &str = "OPENVM_ACCELERATORS_NULL_CASE";

/// Asserts that `case` panics because it passes a NULL pointer.
///
/// The accelerators are `extern "C"` functions, so a panic inside one aborts the process instead
/// of unwinding into the test. The case therefore runs in a child process: this test binary,
/// filtered to `test` (the name of the calling test), with `name` selecting the case. The child
/// skips every other case of the test.
pub(crate) fn assert_null_pointer_panic(test: &str, name: &str, case: impl FnOnce()) {
    if let Ok(selected) = std::env::var(CASE_ENV) {
        if selected == name {
            case();
            // The case returned: exit successfully, which the parent reports as a failure.
            std::process::exit(0);
        }
        return;
    }
    let output = Command::new(std::env::current_exe().expect("test binary path"))
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CASE_ENV, name)
        .output()
        .expect("run the test binary");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && stderr.contains("NULL pointer argument"),
        "{name}: expected a NULL pointer panic, but the child exited with {}:\n{stderr}",
        output.status
    );
}
