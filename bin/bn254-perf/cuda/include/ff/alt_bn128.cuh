// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// BN254 (alt_bn128) Montgomery constants and device-side field typedefs.
//
// The `fp_t` / `fr_t` typedefs are intentionally gated on `__CUDA_ARCH__`, so
// they are visible ONLY in nvcc's device pass. Consumers that need host-
// visible BN254 types (e.g. to satisfy nvcc's host-compile pass on a .cu
// file that uses `fr_t` in a signature) must provide their own host-side
// definition in a `#ifndef __CUDA_ARCH__` block. This header deliberately
// does not ship a host-side implementation so that cuda-common stays free of
// any host-side field-library dependency.

#pragma once

#ifdef __NVCC__
#include <cstdint>

namespace device {
#define TO_CUDA_T(limb64) (uint32_t)(limb64), (uint32_t)(limb64>>32)
    static __device__ __constant__ const uint32_t ALT_BN128_P[8] = {
        TO_CUDA_T(0x3c208c16d87cfd47), TO_CUDA_T(0x97816a916871ca8d),
        TO_CUDA_T(0xb85045b68181585d), TO_CUDA_T(0x30644e72e131a029)
    };
    static __device__ __constant__ const uint32_t ALT_BN128_RR[8] = { /* (1<<512)%P */
        TO_CUDA_T(0xf32cfc5b538afa89), TO_CUDA_T(0xb5e71911d44501fb),
        TO_CUDA_T(0x47ab1eff0a417ff6), TO_CUDA_T(0x06d89f71cab8351f),
    };
    static __device__ __constant__ const uint32_t ALT_BN128_one[8] = { /* (1<<256)%P */
        TO_CUDA_T(0xd35d438dc58f0d9d), TO_CUDA_T(0x0a78eb28f5c70b3d),
        TO_CUDA_T(0x666ea36f7879462c), TO_CUDA_T(0x0e0a77c19a07df2f)
    };
    static __device__ __constant__ const uint32_t ALT_BN128_M0 = 0xe4866389;

    static __device__ __constant__ const uint32_t ALT_BN128_r[8] = {
        TO_CUDA_T(0x43e1f593f0000001), TO_CUDA_T(0x2833e84879b97091),
        TO_CUDA_T(0xb85045b68181585d), TO_CUDA_T(0x30644e72e131a029)
    };
    static __device__ __constant__ const uint32_t ALT_BN128_rRR[8] = { /* (1<<512)%P */
        TO_CUDA_T(0x1bb8e645ae216da7), TO_CUDA_T(0x53fe3ab1e35c59e3),
        TO_CUDA_T(0x8c49833d53bb8085), TO_CUDA_T(0x0216d0b17f4e44a5)
    };
    static __device__ __constant__ const uint32_t ALT_BN128_rone[8] = { /* (1<<256)%P */
        TO_CUDA_T(0xac96341c4ffffffb), TO_CUDA_T(0x36fc76959f60cd29),
        TO_CUDA_T(0x666ea36f7879462e), TO_CUDA_T(0x0e0a77c19a07df2f)
    };
    static __device__ __constant__ const uint32_t ALT_BN128_m0 = 0xefffffff;
}
# ifdef __CUDA_ARCH__   // device-side field types
# include "mont_t.cuh"
typedef mont_t<254, device::ALT_BN128_P, device::ALT_BN128_M0,
                    device::ALT_BN128_RR, device::ALT_BN128_one> fp_t;
typedef mont_t<254, device::ALT_BN128_r, device::ALT_BN128_m0,
                    device::ALT_BN128_rRR, device::ALT_BN128_rone> fr_t;
# else
// Host-side stubs (nvcc's host pass): POD structs of the right size so kernel
// signatures using `fr_t` / `fp_t` by value compile in both passes. The bytes
// are copied directly to the launch parameter buffer — device pass reinterprets
// them as `mont_t<254, ...>`, matching sizeof.
//
// The stub also provides no-op operators so kernel bodies referencing `*`, `+`,
// `sqr`, `.inverse()` type-check in nvcc's host parse; the host pass never
// executes any of these — the device pass links to the real `mont_t` ops.
struct fp_t {
    uint32_t val[8];
    fp_t operator*(const fp_t&) const { return {}; }
    fp_t operator+(const fp_t&) const { return {}; }
    fp_t operator-(const fp_t&) const { return {}; }
    fp_t inverse() const { return {}; }
};
struct fr_t {
    uint32_t val[8];
    fr_t operator*(const fr_t&) const { return {}; }
    fr_t operator+(const fr_t&) const { return {}; }
    fr_t operator-(const fr_t&) const { return {}; }
    fr_t inverse() const { return {}; }
};
inline fp_t sqr(const fp_t&) { return {}; }
inline fr_t sqr(const fr_t&) { return {}; }
# endif

#undef TO_CUDA_T
#endif
