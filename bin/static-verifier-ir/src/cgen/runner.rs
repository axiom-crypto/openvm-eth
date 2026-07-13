//! dlopens the compiled shared object and runs `svir_tracegen` in-process.

use std::path::Path;

use eyre::Result;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use libloading::{Library, Symbol};

type TracegenFn = unsafe extern "C" fn(*const Fr, *mut Fr);

pub struct Compiled {
    // `func` points into `_lib`; field order guarantees func is dropped first.
    func: libloading::os::unix::Symbol<TracegenFn>,
    _lib: Library,
}

impl Compiled {
    pub fn load(so: &Path) -> Result<Self> {
        unsafe {
            let lib = Library::new(so)?;
            let sym: Symbol<'_, TracegenFn> = lib.get(b"svir_tracegen\0")?;
            let func = sym.into_raw();
            Ok(Self { func, _lib: lib })
        }
    }

    pub fn run(&self, inputs: &[Fr], num_slots: usize) -> Vec<Fr> {
        let mut witness = vec![Fr::zero(); num_slots];
        unsafe { (self.func)(inputs.as_ptr(), witness.as_mut_ptr()) };
        witness
    }
}
