use bytes::BufMut;
use openvm_guest_keccak::{keccak256, Keccak256Sponge, OUTPUT_SIZE};
use tiny_keccak::Hasher;

fn reference(bytes: &[u8]) -> [u8; OUTPUT_SIZE] {
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0; OUTPUT_SIZE];
    hasher.finalize(&mut digest);
    digest
}

/// Keccak-256 rate in bytes, mirroring the sponge's own internal constant. Its block boundaries
/// are where the absorb state machine changes behaviour, so the sweeps below are expressed
/// relative to it.
const RATE: usize = 136;

/// Alignment the sponge maintains for buffers handed to the OpenVM instructions, mirroring its
/// internal constant.
const GUEST_ALIGN: usize = 8;

/// Deterministic pseudo-random bytes (xorshift), independent of test order.
fn test_bytes(len: usize, mut seed: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        bytes.extend_from_slice(&seed.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

#[test]
fn known_answers() {
    let empty: [u8; OUTPUT_SIZE] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];
    assert_eq!(keccak256(&[]), empty);

    let abc: [u8; OUTPUT_SIZE] = [
        0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6,
        0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d,
        0x6c, 0x45,
    ];
    assert_eq!(keccak256(b"abc"), abc);
}

#[test]
fn matches_reference_across_lengths() {
    // Covers both sides of every rate-block and 8-byte-word boundary.
    for len in 0..=420 {
        let bytes = test_bytes(len, 0x1234_5678 + len as u64);
        assert_eq!(keccak256(&bytes), reference(&bytes), "length {len}");
    }
    for len in [1000, 4096, 100_000] {
        let bytes = test_bytes(len, len as u64);
        assert_eq!(keccak256(&bytes), reference(&bytes), "length {len}");
    }
}

#[test]
fn matches_reference_at_unaligned_offsets() {
    let bytes = test_bytes(4400, 42);
    for offset in 0..16 {
        for len in [0, 1, 20, 32, 135, 136, 137, 300, 4000] {
            let slice = &bytes[offset..offset + len];
            assert_eq!(keccak256(slice), reference(slice), "offset {offset} length {len}");
        }
    }
}

#[test]
fn streaming_absorb_matches_one_shot() {
    let bytes = test_bytes(1500, 7);
    for chunk_size in [1, 3, 7, 8, 64, 135, 136, 137, 500] {
        let mut sponge = Keccak256Sponge::new();
        for chunk in bytes.chunks(chunk_size) {
            sponge.absorb(chunk);
        }
        assert_eq!(sponge.absorbed_len(), bytes.len());
        assert_eq!(sponge.finalize(), reference(&bytes), "chunk size {chunk_size}");
    }
}

#[test]
fn bufmut_writes_match_one_shot() {
    let bytes = test_bytes(700, 99);
    let mut sponge = Keccak256Sponge::new();
    let mut written = 0;
    // Alternate single-byte and slice writes of growing sizes.
    let mut len = 1;
    while written < bytes.len() {
        sponge.put_u8(bytes[written]);
        written += 1;
        let take = usize::min(len, bytes.len() - written);
        sponge.put_slice(&bytes[written..written + take]);
        written += take;
        len += 13;
    }
    assert_eq!(sponge.absorbed_len(), bytes.len());
    assert_eq!(sponge.finalize(), reference(&bytes));
}

#[test]
fn chunk_mut_writes_match_one_shot() {
    let bytes = test_bytes(1000, 5);
    let mut sponge = Keccak256Sponge::new();
    let mut written = 0;
    let mut step = 1;
    while written < bytes.len() {
        let chunk = sponge.chunk_mut();
        let take = usize::min(usize::min(step, chunk.len()), bytes.len() - written);
        // Fail rather than spin if `chunk_mut` ever hands back an empty slice, which is what it
        // does whenever it stops flushing a full block.
        assert_ne!(take, 0, "chunk_mut returned no room at {written} bytes written");
        // SAFETY: `take` is bounded by both the chunk and the source lengths, and
        // `advance_mut` is passed exactly the number of initialized bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes[written..].as_ptr(), chunk.as_mut_ptr(), take);
            sponge.advance_mut(take);
        }
        written += take;
        step += 3;
    }
    assert_eq!(sponge.absorbed_len(), bytes.len());
    assert_eq!(sponge.finalize(), reference(&bytes));
}

/// Enumerates the absorb state machine's transition table: every `fill` the sponge can hold,
/// against every following input length that selects a different branch.
///
/// [`streaming_absorb_matches_one_shot`] absorbs at a constant chunk size, so the `fill` it
/// presents to `absorb` only ever visits an arithmetic progression — a chunk size of 8 never
/// produces a fill of 3. Enumerating the pair leaves no combination unvisited.
#[test]
fn absorb_matches_reference_from_every_fill() {
    let source = test_bytes(3 * RATE, 0xfeed);
    for prefix in 0..=RATE {
        for len in 0..=RATE + 8 {
            let mut sponge = Keccak256Sponge::new();
            sponge.absorb(&source[..prefix]);
            sponge.absorb(&source[prefix..prefix + len]);
            assert_eq!(sponge.absorbed_len(), prefix + len, "prefix {prefix} len {len}");
            assert_eq!(
                sponge.finalize(),
                reference(&source[..prefix + len]),
                "prefix {prefix} len {len}"
            );
        }
    }
}

/// The sponge absorbs rate-sized chunks straight from the caller's buffer when their pointer is
/// 8-byte aligned, so that choice has to be swept against alignment as well as against `fill`.
///
/// A host run executes the byte-wise stand-in rather than the XORIN instruction, and the stand-in
/// tolerates any alignment. What makes this test meaningful off-target is that `xorin` asserts its
/// length and alignment preconditions for both targets, so admitting a block the instruction could
/// not accept fails here.
#[test]
fn absorb_matches_reference_across_alignments_and_fills() {
    let source = test_bytes(4 * RATE, 0xa11c);
    for align_off in 0..GUEST_ALIGN {
        for prefix in 0..=RATE {
            for len in [RATE - 1, RATE, RATE + 1, 2 * RATE] {
                let start = align_off + prefix;
                let mut sponge = Keccak256Sponge::new();
                sponge.absorb(&source[align_off..start]);
                sponge.absorb(&source[start..start + len]);
                assert_eq!(
                    sponge.finalize(),
                    reference(&source[align_off..start + len]),
                    "align {align_off} prefix {prefix} len {len}"
                );
            }
        }
    }
}

/// `put_u8` and `chunk_mut` write into the staged block directly, so the `flush_if_full` each one
/// performs is what keeps it in bounds when a previous write landed exactly on a block boundary.
/// `absorb` stages an exact fit without flushing, so that state is reachable — and no other test
/// here produces it.
#[test]
fn block_boundary_writes_stay_in_bounds() {
    let source = test_bytes(2 * RATE, 0xb10c);
    // Every split reaches an exactly-full block by a different route through `absorb`.
    for split in 0..=RATE {
        let mut sponge = Keccak256Sponge::new();
        sponge.put_slice(&source[..split]);
        sponge.put_slice(&source[split..RATE]);
        assert_eq!(sponge.absorbed_len(), RATE, "split {split}");
        sponge.put_u8(source[RATE]);
        sponge.put_slice(&source[RATE + 1..RATE + 9]);
        assert_eq!(sponge.absorbed_len(), RATE + 9, "split {split}");
        assert_eq!(sponge.finalize(), reference(&source[..RATE + 9]), "split {split}");

        let mut sponge = Keccak256Sponge::new();
        sponge.put_slice(&source[..split]);
        sponge.put_slice(&source[split..RATE]);
        assert_ne!(sponge.chunk_mut().len(), 0, "chunk_mut found no room, split {split}");
    }
}
