//! Keccak-256 sponge tuned for the OpenVM guest.
//!
//! The guest's default keccak path (`alloy-primitives`' `native-keccak` hook) locks a
//! static hasher and absorbs input through openvm's `native_xorin` wrapper, which
//! allocates aligned staging buffers and copies both the input and the Keccak state
//! whenever a pointer or a length is not 8-byte aligned. RLP-encoded trie nodes,
//! addresses, and storage keys hit those paths constantly, and the staging allocations
//! are never reclaimed by the guest's bump allocator.
//!
//! [`Keccak256Sponge`] keeps an 8-byte-aligned state and rate buffer of its own and
//! only issues XORIN instructions with 8-byte-aligned pointers and lengths, emitted
//! directly without the wrapper's checks. The final partial block is zero-padded to an
//! 8-byte multiple before being absorbed — XOR-ing zero bytes into the state is a
//! no-op — and the sponge padding is applied directly to the state.
//!
//! The [`bytes::BufMut`] implementation lets callers stream serialized data (e.g. RLP
//! encoding) straight into the hash without materializing it in a scratch buffer.

#![no_std]

use core::mem::MaybeUninit;

use bytes::{buf::UninitSlice, BufMut};

/// Keccak-256 sponge rate in bytes.
const RATE: usize = 136;
/// Keccak-f\[1600\] state width in bytes.
const STATE_BYTES: usize = 200;
/// Keccak-256 digest size in bytes.
pub const OUTPUT_SIZE: usize = 32;

/// The Keccak state, aligned so the native XORIN/KECCAKF instructions accept it
/// without staging copies.
#[derive(Debug)]
#[repr(align(8))]
struct State([u8; STATE_BYTES]);

/// Staging buffer for one rate block, aligned for the native XORIN fast path. Left
/// uninitialized on construction: only the `fill`-byte prefix tracked by the sponge is
/// ever initialized, and only initialized bytes are read.
#[derive(Debug)]
#[repr(align(8))]
struct Block(MaybeUninit<[u8; RATE]>);

/// An incremental Keccak-256 hasher.
#[derive(Debug)]
pub struct Keccak256Sponge {
    state: State,
    block: Block,
    /// Initialized prefix of `block` (`0..=RATE`; `RATE` means a full block that is
    /// absorbed lazily by the next operation).
    fill: usize,
    /// Number of rate blocks absorbed so far, tracked for [`Self::absorbed_len`].
    blocks: usize,
}

impl Keccak256Sponge {
    /// Creates an empty sponge.
    pub const fn new() -> Self {
        Self {
            state: State([0; STATE_BYTES]),
            block: Block(MaybeUninit::uninit()),
            fill: 0,
            blocks: 0,
        }
    }

    /// Total number of bytes absorbed so far.
    #[inline]
    pub fn absorbed_len(&self) -> usize {
        self.blocks * RATE + self.fill
    }

    #[inline(always)]
    fn block_ptr(&mut self) -> *mut u8 {
        self.block.0.as_mut_ptr().cast::<u8>()
    }

    /// Copies `bytes` into the staged block. The caller keeps the result within the
    /// block: `fill + bytes.len() <= RATE`.
    #[inline(always)]
    fn stage(&mut self, bytes: &[u8]) {
        debug_assert!(self.fill + bytes.len() <= RATE);
        // SAFETY: the destination range lies within the RATE-byte block, and staging
        // extends the initialized prefix contiguously.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.block_ptr().add(self.fill),
                bytes.len(),
            );
        }
        self.fill += bytes.len();
    }

    #[inline(always)]
    fn flush_if_full(&mut self) {
        if self.fill == RATE {
            let block = self.block_ptr();
            // SAFETY: all RATE staged bytes are initialized and the block is 8-byte
            // aligned.
            unsafe { xorin(&mut self.state, block, RATE) };
            keccakf(&mut self.state);
            self.blocks += 1;
            self.fill = 0;
        }
    }

    /// Absorbs `bytes` into the sponge.
    #[inline]
    pub fn absorb(&mut self, bytes: &[u8]) {
        if self.fill + bytes.len() <= RATE {
            self.stage(bytes);
        } else {
            self.absorb_overflowing(bytes);
        }
    }

    /// Absorb path for inputs that do not fit in the staged block.
    fn absorb_overflowing(&mut self, mut bytes: &[u8]) {
        self.flush_if_full();
        if self.fill != 0 {
            let take = usize::min(RATE - self.fill, bytes.len());
            self.stage(&bytes[..take]);
            bytes = &bytes[take..];
            if bytes.is_empty() {
                return;
            }
            self.flush_if_full();
        }
        while bytes.len() >= RATE {
            let (head, rest) = bytes.split_at(RATE);
            if head.as_ptr().addr() % 8 == 0 {
                // Absorb aligned blocks straight from the input.
                // SAFETY: `head` is RATE initialized bytes and 8-byte aligned.
                unsafe { xorin(&mut self.state, head.as_ptr(), RATE) };
                keccakf(&mut self.state);
                self.blocks += 1;
            } else {
                self.stage(head);
                self.flush_if_full();
            }
            bytes = rest;
        }
        self.stage(bytes);
    }

    /// Applies the Keccak-256 padding and returns the digest.
    ///
    /// The sponge must not be used for further hashing afterwards: absorbing more data
    /// would continue from the squeezed state, not from a fresh one.
    #[inline]
    pub fn finalize(&mut self) -> [u8; OUTPUT_SIZE] {
        self.flush_if_full();
        if self.fill != 0 {
            // Absorb the staged tail zero-padded to an 8-byte multiple; the extra zero
            // bytes leave the state untouched.
            let end = self.fill.next_multiple_of(8);
            // SAFETY: the padded range lies within the RATE-byte block and extends the
            // initialized prefix, so the xorin below reads only initialized bytes.
            unsafe {
                core::ptr::write_bytes(self.block_ptr().add(self.fill), 0, end - self.fill);
                let block = self.block_ptr();
                xorin(&mut self.state, block, end);
            }
        }
        // pad10*1, applied directly to the state.
        self.state.0[self.fill] ^= 0x01;
        self.state.0[RATE - 1] ^= 0x80;
        keccakf(&mut self.state);
        let mut digest = [0; OUTPUT_SIZE];
        digest.copy_from_slice(&self.state.0[..OUTPUT_SIZE]);
        digest
    }
}

impl Default for Keccak256Sponge {
    fn default() -> Self {
        Self::new()
    }
}

/// Streams written bytes into the hash. Writers stage data in the sponge's aligned rate
/// buffer, so hashing serialized data needs no intermediate scratch buffer.
unsafe impl BufMut for Keccak256Sponge {
    #[inline(always)]
    fn remaining_mut(&self) -> usize {
        usize::MAX
    }

    #[inline(always)]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        let fill = self.fill + cnt;
        assert!(fill <= RATE, "advanced {cnt} bytes past the staged keccak block");
        self.fill = fill;
    }

    #[inline(always)]
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.flush_if_full();
        let fill = self.fill;
        let chunk = self.block_ptr();
        // SAFETY: the returned slice covers exactly the unfilled suffix of the block;
        // `advance_mut` extends the initialized prefix only after the caller wrote it.
        unsafe { UninitSlice::from_raw_parts_mut(chunk.add(fill), RATE - fill) }
    }

    #[inline]
    fn put_slice(&mut self, src: &[u8]) {
        self.absorb(src);
    }

    #[inline]
    fn put_u8(&mut self, n: u8) {
        self.flush_if_full();
        let fill = self.fill;
        // SAFETY: `fill < RATE` after the flush above, and the write extends the
        // initialized prefix by one byte.
        unsafe { self.block_ptr().add(fill).write(n) };
        self.fill = fill + 1;
    }
}

/// Computes the Keccak-256 digest of `bytes`.
#[inline]
pub fn keccak256(bytes: &[u8]) -> [u8; OUTPUT_SIZE] {
    let mut sponge = Keccak256Sponge::new();
    sponge.absorb(bytes);
    sponge.finalize()
}

/// XORs `len` bytes at `input` into the front of the sponge state with a single XORIN
/// instruction, emitted directly: the sponge upholds the instruction's alignment
/// requirements by construction, so `native_xorin`'s per-call checks and staging
/// fallback are unnecessary.
///
/// # Safety
///
/// `input` must be valid for `len` initialized bytes, 8-byte aligned, with `len` a
/// multiple of 8 and at most `RATE`.
#[cfg(target_os = "openvm")]
#[inline(always)]
unsafe fn xorin(state: &mut State, input: *const u8, len: usize) {
    use openvm_keccak256_guest::{OPCODE, XORIN_FUNCT3, XORIN_FUNCT7};
    debug_assert!(len <= RATE && len % 8 == 0);
    debug_assert_eq!(input.addr() % 8, 0);
    let mut state_ptr = state.0.as_mut_ptr();
    openvm_platform::custom_insn_r!(
        opcode = OPCODE,
        funct3 = XORIN_FUNCT3,
        funct7 = XORIN_FUNCT7,
        rd = InOut state_ptr,
        rs1 = In input,
        rs2 = In len
    );
}

#[cfg(not(target_os = "openvm"))]
unsafe fn xorin(state: &mut State, input: *const u8, len: usize) {
    // SAFETY: the caller passes `input` valid for `len` initialized bytes.
    let input = unsafe { core::slice::from_raw_parts(input, len) };
    for (state_byte, input_byte) in state.0.iter_mut().zip(input) {
        *state_byte ^= *input_byte;
    }
}

/// Applies the Keccak-f\[1600\] permutation to the state.
#[cfg(target_os = "openvm")]
#[inline(always)]
fn keccakf(state: &mut State) {
    use openvm_keccak256_guest::{KECCAKF_FUNCT3, KECCAKF_FUNCT7, OPCODE};
    let mut state_ptr = state.0.as_mut_ptr();
    openvm_platform::custom_insn_r!(
        opcode = OPCODE,
        funct3 = KECCAKF_FUNCT3,
        funct7 = KECCAKF_FUNCT7,
        rd = InOut state_ptr,
        rs1 = Const "x0",
        rs2 = Const "x0",
    );
}

#[cfg(not(target_os = "openvm"))]
fn keccakf(state: &mut State) {
    let mut lanes = [0u64; 25];
    for (lane, bytes) in lanes.iter_mut().zip(state.0.chunks_exact(8)) {
        *lane = u64::from_le_bytes(bytes.try_into().expect("chunks are 8 bytes"));
    }
    tiny_keccak::keccakf(&mut lanes);
    for (lane, bytes) in lanes.iter().zip(state.0.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
}
