// Single-thread BN254-Fr micro-benchmarks. Every kernel is launched with
// <<<1, 1>>>: one CUDA thread runs the whole chain, so we're measuring per-op
// device-side Montgomery arithmetic latency, not throughput.

#include <cstdint>
#include <cuda_runtime.h>

// Pulls in device::ALT_BN128_r and the `fr_t = mont_t<254, ...>` alias.
#include "ff/alt_bn128.cuh"

// ---- Kernels ---------------------------------------------------------------

// Fr multiplication chain: x <- x * a (repeated). One Montgomery mul per iter.
__global__ void mul_chain_kernel(fr_t* out, fr_t x, fr_t a, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        x = x * a;
    }
    *out = x;
}

// Fr squaring chain: x <- x * x (repeated). One Montgomery sqr per iter.
__global__ void sqr_chain_kernel(fr_t* out, fr_t x, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        x = sqr(x);
    }
    *out = x;
}

// Poseidon2 sbox chain: x <- x^5 (repeated). x^5 = (x^2)^2 * x — 3 muls per iter.
__global__ void sbox_chain_kernel(fr_t* out, fr_t x, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        fr_t x2 = sqr(x);
        fr_t x4 = sqr(x2);
        x = x * x4;
    }
    *out = x;
}

// Fused mul-add chain: x <- x*a + b. One mul + one add per iter.
__global__ void mul_add_chain_kernel(fr_t* out, fr_t x, fr_t a, fr_t b, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        x = x * a + b;
    }
    *out = x;
}

// Fr add chain: x <- x + a. One modular add per iter.
__global__ void add_chain_kernel(fr_t* out, fr_t x, fr_t a, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        x = x + a;
    }
    *out = x;
}

// Fr inversion chain: x <- x.invert() + a. Adding `a` breaks the trivial
// two-cycle `x -> 1/x -> x` and forces every iteration to run the binary-GCD
// inverse on a fresh value.
__global__ void inv_chain_kernel(fr_t* out, fr_t x, fr_t a, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        x = x.inverse() + a;
    }
    *out = x;
}

// ---- Host launcher ---------------------------------------------------------

// Result of a single benchmarked kernel launch:
// - elapsed_ms: wall time between cudaEventRecord start/stop (kernel-only).
// - result: 32-byte little-endian Fr limbs read back from device.
struct BenchResult {
    float elapsed_ms;
    uint64_t result[4];
};

// Op ids for `bn254_perf_run`. Kept in sync with `Op` in src/main.rs.
enum Op {
    OP_MUL     = 0,
    OP_SQR     = 1,
    OP_SBOX    = 2,
    OP_MUL_ADD = 3,
    OP_ADD     = 4,
    OP_INV     = 5,
};

// Interpret the 4 x u64 payloads as raw fr_t (Montgomery form). This is safe
// because halo2curves-axiom's Fr and sppark's mont_t both store BN254 scalars
// as little-endian 256-bit values in Montgomery form with the same modulus and
// M0 = 0xc2e1f593efffffff (low 32 bits match sppark's 0xefffffff).
static inline void copy_fr(fr_t& dst, const uint64_t src[4]) {
    uint32_t* dst_u32 = reinterpret_cast<uint32_t*>(&dst);
    for (int i = 0; i < 4; i++) {
        dst_u32[2 * i]     = (uint32_t)(src[i] & 0xffffffffu);
        dst_u32[2 * i + 1] = (uint32_t)(src[i] >> 32);
    }
}

extern "C" int bn254_perf_run(
    int op,
    const uint64_t x_limbs[4],
    const uint64_t a_limbs[4],
    const uint64_t b_limbs[4],
    uint64_t n,
    BenchResult* out) {

    fr_t x, a, b;
    copy_fr(x, x_limbs);
    copy_fr(a, a_limbs);
    copy_fr(b, b_limbs);

    fr_t* d_out = nullptr;
    cudaError_t rc = cudaMalloc(&d_out, sizeof(fr_t));
    if (rc != cudaSuccess) {
        return static_cast<int>(rc);
    }

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    cudaEventRecord(start);
    switch (op) {
        case OP_MUL:
            mul_chain_kernel<<<1, 1>>>(d_out, x, a, n);
            break;
        case OP_SQR:
            sqr_chain_kernel<<<1, 1>>>(d_out, x, n);
            break;
        case OP_SBOX:
            sbox_chain_kernel<<<1, 1>>>(d_out, x, n);
            break;
        case OP_MUL_ADD:
            mul_add_chain_kernel<<<1, 1>>>(d_out, x, a, b, n);
            break;
        case OP_ADD:
            add_chain_kernel<<<1, 1>>>(d_out, x, a, n);
            break;
        case OP_INV:
            inv_chain_kernel<<<1, 1>>>(d_out, x, a, n);
            break;
        default:
            cudaFree(d_out);
            cudaEventDestroy(start);
            cudaEventDestroy(stop);
            return -1;
    }
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);

    float elapsed = 0.0f;
    cudaEventElapsedTime(&elapsed, start, stop);
    out->elapsed_ms = elapsed;

    // Copy 32 bytes back — reinterpret device fr_t as u64[4].
    rc = cudaMemcpy(out->result, d_out, sizeof(fr_t), cudaMemcpyDeviceToHost);

    cudaFree(d_out);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    return static_cast<int>(rc);
}
