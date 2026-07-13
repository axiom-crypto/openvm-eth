// Hand-written Fr/BabyBear opcode implementations for generated tracegen C.
// fr_t is the halo2curves bn256::Fr layout: 4 LE u64 limbs, Montgomery form
// (R = 2^256). The Rust runner asserts this layout at startup.
#pragma once

#include <stdint.h>

typedef struct {
    uint64_t l[4];
} fr_t;

typedef unsigned __int128 u128;

extern const fr_t IR_CONSTS[];

// API called from the generated chunk files. Definitions live in ops.c
// (compiled once at -O2); chunks are straight-line calls compiled at -O0.
fr_t fr_add(fr_t a, fr_t b);
fr_t fr_sub(fr_t a, fr_t b);
fr_t fr_mul(fr_t a, fr_t b);
fr_t fr_neg(fr_t a);
fr_t fr_mul_add(fr_t a, fr_t b, fr_t c);
fr_t fr_sub_mul(fr_t a, fr_t b, fr_t c);
fr_t fr_select(fr_t a, fr_t b, fr_t sel);
void op_is_zero(fr_t *out, fr_t a);
void op_divmod_u32(fr_t *out, fr_t a, uint32_t d);
void op_decompose(fr_t *out, fr_t a, uint32_t num_limbs, uint32_t limb_bits);
void op_bn_to_bb5(fr_t *out, fr_t a);
fr_t op_bb_reduce(fr_t a);
fr_t op_bb_div(fr_t a, fr_t b);
void op_ext4_mul(fr_t *out, fr_t a0, fr_t a1, fr_t a2, fr_t a3, fr_t b0, fr_t b1, fr_t b2,
                 fr_t b3);
void op_ext4_div(fr_t *out, fr_t a0, fr_t a1, fr_t a2, fr_t a3, fr_t b0, fr_t b1, fr_t b2,
                 fr_t b3);
void op_poseidon2_t3(fr_t *out, fr_t in0, fr_t in1, fr_t in2);
void op_poseidon2_t2(fr_t *out, fr_t in0, fr_t in1);

#ifdef SVIR_OPCODES_IMPL

#include "fr_constants.h"
#include "poseidon2_constants.h"

// ---------------------------------------------------------------------------
// u256 helpers (canonical, non-Montgomery integers as 4 LE u64 limbs)
// ---------------------------------------------------------------------------

static inline int u256_gte(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 1;
}

static inline int u256_gt(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 0;
}

static inline int u256_is_zero(const uint64_t a[4]) {
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}

// quotient into q, returns remainder (divisor is a nonzero u32)
static inline uint32_t u256_divmod_u32(uint64_t q[4], const uint64_t v[4], uint32_t d) {
    u128 rem = 0;
    for (int i = 3; i >= 0; i--) {
        u128 cur = (rem << 64) | v[i];
        q[i] = (uint64_t)(cur / d);
        rem = cur % d;
    }
    return (uint32_t)rem;
}

// extract `count` (<= 64) bits starting at bit `start`
static inline uint64_t u256_extract_bits(const uint64_t v[4], uint32_t start, uint32_t count) {
    uint32_t word = start >> 6;
    uint32_t off = start & 63;
    uint64_t lo = word < 4 ? (v[word] >> off) : 0;
    if (off != 0 && word + 1 < 4) lo |= v[word + 1] << (64 - off);
    if (count < 64) lo &= (1ULL << count) - 1;
    return lo;
}

// ---------------------------------------------------------------------------
// Fr arithmetic (Montgomery)
// ---------------------------------------------------------------------------

static inline fr_t fr_sub_p(fr_t a) {
    fr_t r;
    u128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        u128 t = (u128)a.l[i] - FR_MODULUS.l[i] - borrow;
        r.l[i] = (uint64_t)t;
        borrow = (t >> 64) & 1;
    }
    return r;
}

fr_t fr_add(fr_t a, fr_t b) {
    fr_t r;
    u128 carry = 0;
    for (int i = 0; i < 4; i++) {
        u128 t = (u128)a.l[i] + b.l[i] + carry;
        r.l[i] = (uint64_t)t;
        carry = t >> 64;
    }
    if (u256_gte(r.l, FR_MODULUS.l)) r = fr_sub_p(r);
    return r;
}

fr_t fr_sub(fr_t a, fr_t b) {
    fr_t r;
    u128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        u128 t = (u128)a.l[i] - b.l[i] - borrow;
        r.l[i] = (uint64_t)t;
        borrow = (t >> 64) & 1;
    }
    if (borrow) {
        u128 carry = 0;
        for (int i = 0; i < 4; i++) {
            u128 t = (u128)r.l[i] + FR_MODULUS.l[i] + carry;
            r.l[i] = (uint64_t)t;
            carry = t >> 64;
        }
    }
    return r;
}

fr_t fr_neg(fr_t a) {
    if (u256_is_zero(a.l)) return a;
    fr_t r;
    u128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        u128 t = (u128)FR_MODULUS.l[i] - a.l[i] - borrow;
        r.l[i] = (uint64_t)t;
        borrow = (t >> 64) & 1;
    }
    return r;
}

// CIOS Montgomery multiplication
fr_t fr_mul(fr_t a, fr_t b) {
    uint64_t t[6] = {0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; i++) {
        u128 carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 v = (u128)t[j] + (u128)a.l[j] * b.l[i] + carry;
            t[j] = (uint64_t)v;
            carry = v >> 64;
        }
        u128 v = (u128)t[4] + carry;
        t[4] = (uint64_t)v;
        t[5] = (uint64_t)(v >> 64);

        uint64_t m = t[0] * FR_INV;
        u128 v2 = (u128)t[0] + (u128)m * FR_MODULUS.l[0];
        carry = v2 >> 64;
        for (int j = 1; j < 4; j++) {
            u128 v3 = (u128)t[j] + (u128)m * FR_MODULUS.l[j] + carry;
            t[j - 1] = (uint64_t)v3;
            carry = v3 >> 64;
        }
        u128 v4 = (u128)t[4] + carry;
        t[3] = (uint64_t)v4;
        t[4] = t[5] + (uint64_t)(v4 >> 64);
    }
    fr_t r = {{t[0], t[1], t[2], t[3]}};
    if (t[4] || u256_gte(r.l, FR_MODULUS.l)) r = fr_sub_p(r);
    return r;
}

static inline fr_t fr_from_mont(fr_t a) {
    fr_t one = {{1, 0, 0, 0}};
    return fr_mul(a, one);
}

static inline fr_t fr_to_mont(fr_t a) {
    return fr_mul(a, FR_R2);
}

static inline fr_t fr_from_u64(uint64_t x) {
    fr_t v = {{x, 0, 0, 0}};
    return fr_to_mont(v);
}

// Fermat inversion; a must be nonzero.
static inline fr_t fr_inv(fr_t a) {
    fr_t r = FR_ONE_MONT;
    for (int i = 255; i >= 0; i--) {
        r = fr_mul(r, r);
        if ((FR_P_MINUS_2[i >> 6] >> (i & 63)) & 1) r = fr_mul(r, a);
    }
    return r;
}

fr_t fr_mul_add(fr_t a, fr_t b, fr_t c) {
    return fr_add(fr_mul(a, b), c);
}

fr_t fr_sub_mul(fr_t a, fr_t b, fr_t c) {
    return fr_sub(a, fr_mul(b, c));
}

fr_t fr_select(fr_t a, fr_t b, fr_t sel) {
    return fr_add(fr_mul(fr_sub(a, b), sel), b);
}

// ---------------------------------------------------------------------------
// BabyBear helpers (canonical u32 residues)
// ---------------------------------------------------------------------------

// Reduce the signed representative (threshold (p-1)/2, matching halo2-base
// fe_to_bigint) into canonical [0, BB_P).
static inline uint32_t fr_to_bb_u32(fr_t a) {
    fr_t c = fr_from_mont(a);
    uint64_t q[4];
    uint32_t r = u256_divmod_u32(q, c.l, BB_P);
    if (u256_gt(c.l, FR_HALF_P)) {
        // signed = canonical - p, so subtract (p mod BB_P)
        r = (uint32_t)(((uint64_t)r + BB_P - FR_P_MOD_BB) % BB_P);
    }
    return r;
}

static inline uint32_t bb_mul_u32(uint32_t a, uint32_t b) {
    return (uint32_t)(((uint64_t)a * b) % BB_P);
}

static inline uint32_t bb_inv_u32(uint32_t a) {
    uint32_t r = 1;
    uint64_t e = (uint64_t)BB_P - 2;
    while (e) {
        if (e & 1) r = bb_mul_u32(r, a);
        a = bb_mul_u32(a, a);
        e >>= 1;
    }
    return r;
}

typedef struct {
    uint32_t c[4];
} bb4_t;

// binomial extension product, x^4 = BB_W
static inline bb4_t bb4_mul(bb4_t a, bb4_t b) {
    uint64_t low[7] = {0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            low[i + j] = (low[i + j] + (uint64_t)a.c[i] * b.c[j]) % BB_P;
    bb4_t r;
    for (int s = 0; s < 4; s++) {
        uint64_t v = low[s];
        if (s < 3) v = (v + (uint64_t)BB_W * low[s + 4]) % BB_P;
        r.c[s] = (uint32_t)v;
    }
    return r;
}

// Fermat inversion in the quartic extension: a^(BB_P^4 - 2). Rare op, so
// simplicity over speed.
static inline bb4_t bb4_inv(bb4_t a) {
    u128 e = (u128)BB_P * BB_P;
    e = e * e - 2;
    bb4_t r = {{1, 0, 0, 0}};
    while (e) {
        if (e & 1) r = bb4_mul(r, a);
        a = bb4_mul(a, a);
        e >>= 1;
    }
    return r;
}

// ---------------------------------------------------------------------------
// Hint / multi-output ops (write consecutive witness slots)
// ---------------------------------------------------------------------------

void op_is_zero(fr_t *out, fr_t a) {
    if (u256_is_zero(a.l)) {
        fr_t z = {{0, 0, 0, 0}};
        out[0] = z;
        out[1] = FR_ONE_MONT;
    } else {
        fr_t z = {{0, 0, 0, 0}};
        out[0] = fr_inv(a);
        out[1] = z;
    }
}

void op_divmod_u32(fr_t *out, fr_t a, uint32_t d) {
    fr_t c = fr_from_mont(a);
    uint64_t q[4];
    uint32_t r = u256_divmod_u32(q, c.l, d);
    fr_t qf = {{q[0], q[1], q[2], q[3]}};
    out[0] = fr_to_mont(qf);
    out[1] = fr_from_u64(r);
}

void op_decompose(fr_t *out, fr_t a, uint32_t num_limbs, uint32_t limb_bits) {
    fr_t c = fr_from_mont(a);
    for (uint32_t i = 0; i < num_limbs; i++)
        out[i] = fr_from_u64(u256_extract_bits(c.l, i * limb_bits, limb_bits));
}

void op_bn_to_bb5(fr_t *out, fr_t a) {
    fr_t c = fr_from_mont(a);
    uint64_t v[4] = {c.l[0], c.l[1], c.l[2], c.l[3]};
    for (int i = 0; i < 5; i++) {
        uint64_t q[4];
        uint32_t r = u256_divmod_u32(q, v, BB_P);
        out[i] = fr_from_u64(r);
        v[0] = q[0];
        v[1] = q[1];
        v[2] = q[2];
        v[3] = q[3];
    }
    fr_t top = {{v[0], v[1], v[2], v[3]}};
    out[5] = fr_to_mont(top);
}

fr_t op_bb_reduce(fr_t a) {
    return fr_from_u64(fr_to_bb_u32(a));
}

fr_t op_bb_div(fr_t a, fr_t b) {
    uint32_t ar = fr_to_bb_u32(a);
    uint32_t br = fr_to_bb_u32(b);
    return fr_from_u64(bb_mul_u32(ar, bb_inv_u32(br)));
}

void op_ext4_mul(fr_t *out, fr_t a0, fr_t a1, fr_t a2, fr_t a3, fr_t b0,
                               fr_t b1, fr_t b2, fr_t b3) {
    fr_t a[4] = {a0, a1, a2, a3};
    fr_t b[4] = {b0, b1, b2, b3};
    fr_t zero = {{0, 0, 0, 0}};
    fr_t low[7] = {zero, zero, zero, zero, zero, zero, zero};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) low[i + j] = fr_add(low[i + j], fr_mul(a[i], b[j]));
    for (int s = 0; s < 4; s++)
        out[s] = s < 3 ? fr_add(low[s], fr_mul(FR_BB_W_MONT, low[s + 4])) : low[s];
}

void op_ext4_div(fr_t *out, fr_t a0, fr_t a1, fr_t a2, fr_t a3, fr_t b0,
                               fr_t b1, fr_t b2, fr_t b3) {
    bb4_t a = {{fr_to_bb_u32(a0), fr_to_bb_u32(a1), fr_to_bb_u32(a2), fr_to_bb_u32(a3)}};
    bb4_t b = {{fr_to_bb_u32(b0), fr_to_bb_u32(b1), fr_to_bb_u32(b2), fr_to_bb_u32(b3)}};
    bb4_t r = bb4_mul(a, bb4_inv(b));
    for (int i = 0; i < 4; i++) out[i] = fr_from_u64(r.c[i]);
}

// ---------------------------------------------------------------------------
// Poseidon2 permutations
// ---------------------------------------------------------------------------

static inline fr_t fr_x5(fr_t x) {
    fr_t x2 = fr_mul(x, x);
    fr_t x4 = fr_mul(x2, x2);
    return fr_mul(x, x4);
}

void op_poseidon2_t3(fr_t *out, fr_t in0, fr_t in1, fr_t in2) {
    fr_t s0 = in0, s1 = in1, s2 = in2;
    fr_t sum = fr_add(fr_add(s0, s1), s2);
    s0 = fr_add(s0, sum);
    s1 = fr_add(s1, sum);
    s2 = fr_add(s2, sum);
    for (int r = 0; r < P2T3_ROUNDS_F / 2; r++) {
        s0 = fr_x5(fr_add(s0, P2T3_EXTERNAL_RC[r][0]));
        s1 = fr_x5(fr_add(s1, P2T3_EXTERNAL_RC[r][1]));
        s2 = fr_x5(fr_add(s2, P2T3_EXTERNAL_RC[r][2]));
        sum = fr_add(fr_add(s0, s1), s2);
        s0 = fr_add(s0, sum);
        s1 = fr_add(s1, sum);
        s2 = fr_add(s2, sum);
    }
    for (int r = 0; r < P2T3_ROUNDS_P; r++) {
        s0 = fr_x5(fr_add(s0, P2T3_INTERNAL_RC[r]));
        sum = fr_add(fr_add(s0, s1), s2);
        s0 = fr_add(fr_mul(s0, P2T3_DIAG[0]), sum);
        s1 = fr_add(fr_mul(s1, P2T3_DIAG[1]), sum);
        s2 = fr_add(fr_mul(s2, P2T3_DIAG[2]), sum);
    }
    for (int r = P2T3_ROUNDS_F / 2; r < P2T3_ROUNDS_F; r++) {
        s0 = fr_x5(fr_add(s0, P2T3_EXTERNAL_RC[r][0]));
        s1 = fr_x5(fr_add(s1, P2T3_EXTERNAL_RC[r][1]));
        s2 = fr_x5(fr_add(s2, P2T3_EXTERNAL_RC[r][2]));
        sum = fr_add(fr_add(s0, s1), s2);
        s0 = fr_add(s0, sum);
        s1 = fr_add(s1, sum);
        s2 = fr_add(s2, sum);
    }
    out[0] = s0;
    out[1] = s1;
    out[2] = s2;
}

void op_poseidon2_t2(fr_t *out, fr_t in0, fr_t in1) {
    fr_t s0 = in0, s1 = in1;
    fr_t sum = fr_add(s0, s1);
    s0 = fr_add(s0, sum);
    s1 = fr_add(s1, sum);
    for (int r = 0; r < P2T2_ROUNDS_F / 2; r++) {
        s0 = fr_x5(fr_add(s0, P2T2_EXTERNAL_RC[r][0]));
        s1 = fr_x5(fr_add(s1, P2T2_EXTERNAL_RC[r][1]));
        sum = fr_add(s0, s1);
        s0 = fr_add(s0, sum);
        s1 = fr_add(s1, sum);
    }
    for (int r = 0; r < P2T2_ROUNDS_P; r++) {
        s0 = fr_x5(fr_add(s0, P2T2_INTERNAL_RC[r]));
        sum = fr_add(s0, s1);
        s0 = fr_add(fr_mul(s0, P2T2_DIAG[0]), sum);
        s1 = fr_add(fr_mul(s1, P2T2_DIAG[1]), sum);
    }
    for (int r = P2T2_ROUNDS_F / 2; r < P2T2_ROUNDS_F; r++) {
        s0 = fr_x5(fr_add(s0, P2T2_EXTERNAL_RC[r][0]));
        s1 = fr_x5(fr_add(s1, P2T2_EXTERNAL_RC[r][1]));
        sum = fr_add(s0, s1);
        s0 = fr_add(s0, sum);
        s1 = fr_add(s1, sum);
    }
    out[0] = s0;
    out[1] = s1;
}

#endif // SVIR_OPCODES_IMPL
