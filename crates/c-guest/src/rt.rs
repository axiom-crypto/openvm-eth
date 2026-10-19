//! Program startup and termination.
//!
//! OpenVM's `__start` calls `main` and then exits with code 0. `build.sh` merges the library with
//! `--wrap=main`, so `__start` calls [`__wrap_main`] instead, and then makes that symbol local, so
//! that it doesn't clash with a program that wraps `main` itself. [`__wrap_main`]:
//!
//! 1. runs the static constructors: `.preinit_array`, then `.init_array`;
//! 2. calls the program's `int main(void)` (as `__real_main`);
//! 3. calls [`exit`] with its return value.
//!
//! [`exit`] calls the functions registered with [`atexit`] and [`__cxa_atexit`] (C++ compilers
//! register static destructors there) in the reverse order of their registration, then the static
//! destructors of `.fini_array` in reverse order, and terminates. [`_Exit`] terminates at once.
//!
//! An exit status of 0 is a successful termination (exit code 0), any other status an abnormal one.
//! OpenVM's exit code is a byte, so a non-zero status exits with its low byte, or with 1 when the
//! low byte is 0. [`abort`] and failed assertions ([`__assert_fail`] for glibc's `assert.h`,
//! [`__assert_func`] for newlib's) exit with code 1, like a Rust panic.
//!
//! The linker must define the bounds of the constructor and destructor arrays
//! (`__init_array_start` and so on), as GNU ld and LLD do with their default linker scripts.

use alloc::{format, vec::Vec};
use core::ffi::{c_char, c_int, c_uint, c_void, CStr};

/// An entry of `.preinit_array`, `.init_array` or `.fini_array`.
type ArrayFn = Option<unsafe extern "C" fn()>;

unsafe extern "C" {
    /// The program's `main`, which `--wrap=main` links as `__real_main`.
    fn __real_main() -> c_int;
}

/// A function registered to run at [`exit`].
enum ExitHandler {
    /// Registered with [`atexit`].
    Plain(unsafe extern "C" fn()),
    /// Registered with [`__cxa_atexit`].
    WithArg(unsafe extern "C" fn(*mut c_void), *mut c_void),
}

/// The functions registered to run at [`exit`], in the order of their registration.
static mut EXIT_HANDLERS: Vec<ExitHandler> = Vec::new();
/// Whether [`exit`] has started to run the `.fini_array` destructors.
static mut FINI_STARTED: bool = false;

/// The address of the linker-defined symbol `$symbol`, as a pointer to array entries.
///
/// It expands to an `asm!` that only computes the address, to be used in an `unsafe` block.
macro_rules! array_bound {
    ($symbol:literal) => {{
        let address: *const ArrayFn;
        core::arch::asm!(
            concat!("la {0}, ", $symbol),
            out(reg) address,
            options(nomem, nostack, preserves_flags),
        );
        address
    }};
}

/// Calls the functions of the array from `start` to `end` in order, or in reverse order.
///
/// # Safety
///
/// `start..end` must be an array of [`ArrayFn`] entries, such as `.init_array`.
unsafe fn call_array(start: *const ArrayFn, end: *const ArrayFn, reverse: bool) {
    let count = (end as usize).saturating_sub(start as usize) / size_of::<ArrayFn>();
    for i in 0..count {
        let index = if reverse { count - 1 - i } else { i };
        // SAFETY: the caller guarantees that `start..end` is an array of entries.
        if let Some(function) = unsafe { start.add(index).read() } {
            // SAFETY: the compiler put the function in the array to be called this way.
            unsafe { function() };
        }
    }
}

/// Runs the static constructors, calls the C `main` and passes its return value to [`exit`].
///
/// See the [module documentation](self).
#[unsafe(no_mangle)]
pub extern "C" fn __wrap_main() {
    // SAFETY: the linker defines the bounds of the arrays, and `__real_main` is the program's
    // `int main(void)`.
    unsafe {
        call_array(
            array_bound!("__preinit_array_start"),
            array_bound!("__preinit_array_end"),
            false,
        );
        call_array(array_bound!("__init_array_start"), array_bound!("__init_array_end"), false);
        exit(__real_main())
    }
}

/// Registers `function` to run at [`exit`]. Returns 0, or -1 if `function` is NULL.
///
/// # Safety
///
/// `function` must be safe to call when the program exits. The guest is single-threaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atexit(function: Option<unsafe extern "C" fn()>) -> c_int {
    let Some(function) = function else {
        return -1;
    };
    // SAFETY: the guest is single-threaded, so nothing else accesses `EXIT_HANDLERS`.
    unsafe { (*&raw mut EXIT_HANDLERS).push(ExitHandler::Plain(function)) };
    0
}

/// Registers `function(arg)` to run at [`exit`], as C++ compilers do for the destructor of a
/// static object. Returns 0, or -1 if `function` is NULL. The program is a single DSO, so the DSO
/// handle doesn't matter.
///
/// # Safety
///
/// `function(arg)` must be safe to call when the program exits. The guest is single-threaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_atexit(
    function: Option<unsafe extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    _dso_handle: *mut c_void,
) -> c_int {
    let Some(function) = function else {
        return -1;
    };
    // SAFETY: the guest is single-threaded, so nothing else accesses `EXIT_HANDLERS`.
    unsafe { (*&raw mut EXIT_HANDLERS).push(ExitHandler::WithArg(function, arg)) };
    0
}

/// The DSO handle that C++ compilers pass to [`__cxa_atexit`].
#[unsafe(no_mangle)]
pub static __dso_handle: u8 = 0;

/// Runs the exit handlers and the static destructors, and terminates with `status`.
///
/// A handler or destructor that calls `exit` again continues with the ones that haven't run yet.
#[unsafe(no_mangle)]
pub extern "C" fn exit(status: c_int) -> ! {
    // SAFETY: the guest is single-threaded, so nothing else accesses `EXIT_HANDLERS` or
    // `FINI_STARTED`. Each handler is removed before it runs.
    unsafe {
        while let Some(handler) = (*&raw mut EXIT_HANDLERS).pop() {
            match handler {
                ExitHandler::Plain(function) => function(),
                ExitHandler::WithArg(function, arg) => function(arg),
            }
        }
        if !FINI_STARTED {
            FINI_STARTED = true;
            call_array(array_bound!("__fini_array_start"), array_bound!("__fini_array_end"), true);
        }
    }
    terminate(status)
}

/// Terminates with `status` without running the exit handlers or the static destructors.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn _Exit(status: c_int) -> ! {
    terminate(status)
}

/// Terminates abnormally, with exit code 1.
#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    openvm::process::panic()
}

/// Reports a failed `assert` (glibc's `assert.h`) and calls [`abort`].
///
/// # Safety
///
/// Each pointer must be NULL or point to a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __assert_fail(
    assertion: *const c_char,
    file: *const c_char,
    line: c_uint,
    function: *const c_char,
) -> ! {
    // SAFETY: as the caller guarantees.
    unsafe { assertion_failed(assertion, file, line, function) }
}

/// Reports a failed `assert` (newlib's `assert.h`) and calls [`abort`].
///
/// # Safety
///
/// Each pointer must be NULL or point to a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __assert_func(
    file: *const c_char,
    line: c_int,
    function: *const c_char,
    assertion: *const c_char,
) -> ! {
    // SAFETY: as the caller guarantees.
    unsafe { assertion_failed(assertion, file, line, function) }
}

/// Prints the failed assertion and calls [`abort`].
///
/// # Safety
///
/// Each pointer must be NULL or point to a NUL-terminated string.
unsafe fn assertion_failed(
    assertion: *const c_char,
    file: *const c_char,
    line: impl core::fmt::Display,
    function: *const c_char,
) -> ! {
    // SAFETY: as the caller guarantees.
    let [assertion, file, function] = [assertion, file, function].map(|s| unsafe { c_str(s) });
    openvm::io::println(format!("{file}:{line}: {function}: Assertion `{assertion}' failed."));
    abort()
}

/// The string at `s`, or `"?"` if `s` is NULL or not UTF-8.
///
/// # Safety
///
/// `s` must be NULL or point to a NUL-terminated string.
unsafe fn c_str<'a>(s: *const c_char) -> &'a str {
    if s.is_null() {
        return "?";
    }
    // SAFETY: the caller guarantees that `s` points to a NUL-terminated string.
    unsafe { CStr::from_ptr(s) }.to_str().unwrap_or("?")
}

/// Terminates with exit status `status` (see the [module documentation](self)).
fn terminate(status: c_int) -> ! {
    if status == 0 {
        openvm::process::exit();
    }
    // OpenVM's exit code is an immediate of its terminate instruction, so each code needs an
    // instruction of its own.
    macro_rules! terminate_with_code {
        ($code:expr; $($n:literal)+) => {
            match $code {
                $($n => openvm::platform::rust_rt::terminate::<$n>(),)+
                _ => openvm::process::panic(),
            }
        };
    }
    terminate_with_code!(status as u8;
        1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
        33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62
        63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92
        93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116
        117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138
        139 140 141 142 143 144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160
        161 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182
        183 184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203 204
        205 206 207 208 209 210 211 212 213 214 215 216 217 218 219 220 221 222 223 224 225 226
        227 228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248
        249 250 251 252 253 254 255
    )
}
