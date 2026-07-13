//! Compiles the generated C files into a shared object with `cc`.

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

use eyre::{eyre, Result};

fn cc() -> String {
    std::env::var("SVIR_CC").unwrap_or_else(|_| "cc".into())
}

/// Flags for the generated chunk files: straight-line calls, so -O0 keeps
/// gcc's time/memory linear (higher levels blow up on the huge functions).
fn chunk_cflags() -> Vec<String> {
    match std::env::var("SVIR_CFLAGS") {
        Ok(f) => f.split_whitespace().map(String::from).collect(),
        Err(_) => vec!["-O0".into()],
    }
}

/// Flags for the hot field-arithmetic TU (ops.c) and other small files.
fn ops_cflags() -> Vec<String> {
    match std::env::var("SVIR_OPS_CFLAGS") {
        Ok(f) => f.split_whitespace().map(String::from).collect(),
        // The .so is built and dlopened on the same machine, so -march=native
        // is always safe and gives mulx/adx for the Montgomery mul.
        Err(_) => vec!["-O3".into(), "-march=native".into()],
    }
}

fn is_chunk(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("chunks_"))
}

/// Compile each `.c` file to an object (in parallel across threads), then link
/// them into `tracegen.so` in `dir`. Returns the path to the shared object.
pub fn compile(dir: &Path, c_files: &[PathBuf]) -> Result<PathBuf> {
    let cc = cc();
    let chunk_flags = chunk_cflags();
    let ops_flags = ops_cflags();

    let objs: Vec<PathBuf> = c_files.iter().map(|c| c.with_extension("o")).collect();

    let next = AtomicUsize::new(0);
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(c_files.len().max(1));

    std::thread::scope(|s| {
        for _ in 0..n_threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= c_files.len() {
                    break;
                }
                let flags = if is_chunk(&c_files[i]) { &chunk_flags } else { &ops_flags };
                let out = Command::new(&cc)
                    .args(flags)
                    .arg("-fPIC")
                    .arg("-c")
                    .arg(&c_files[i])
                    .arg("-o")
                    .arg(&objs[i])
                    .output();
                match out {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => errors.lock().unwrap().push(format!(
                        "{}: {}",
                        c_files[i].display(),
                        String::from_utf8_lossy(&o.stderr)
                    )),
                    Err(e) => errors
                        .lock()
                        .unwrap()
                        .push(format!("{}: spawn {cc}: {e}", c_files[i].display())),
                }
            });
        }
    });

    let errors = errors.into_inner().unwrap();
    if !errors.is_empty() {
        return Err(eyre!("cc failed:\n{}", errors.join("\n")));
    }

    let so = dir.join("tracegen.so");
    let out = Command::new(&cc).arg("-shared").args(&objs).arg("-o").arg(&so).output()?;
    if !out.status.success() {
        return Err(eyre!("link failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(so)
}
