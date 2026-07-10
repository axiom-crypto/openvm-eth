# Chip trait summary

Guide to the four abstractions in `src/repr.rs` and `src/chip/*`. For each
method: signature, semantics, its internal dependencies, the tracegen call sites
(files under `src/verify/`, `src/transcript.rs`, `src/hash/`), and the original
implementation in `halo2-base` or `openvm-static-verifier`.

## Overview

Trait hierarchy (leaf → root):

```
FieldRepr           (repr.rs)
   ├─ FrRepr        eager Fr::invert()
   └─ FractionRepr  Rational(num, denom) — invert deferred
        │
        ▼
GateChip<R>          concrete, not a trait (src/chip/gate.rs)
raw Fr-level arithmetic + selection primitives
        │
        ▼
RangeExt             (src/chip/mod.rs)  ── RangeChip<R> implements it
range-check + integer div_mod
        │
        ▼
BabyBearExt          (src/chip/mod.rs)  ── BabyBearChip<R> implements it
BabyBear-in-Fr with lazy `max_bits` reduction
        │
        ▼
BabyBearExtInst      (src/chip/mod.rs)  ── BabyBearExt4Chip<R> implements it
quartic-extension arithmetic on top of BabyBearExt
```

`constrained_verify` in `src/verify/full_pipeline.rs` takes
`&impl BabyBearExtInst` and drives the whole call graph through these traits.

---

## `FieldRepr` (src/repr.rs)

Represents a single field element used inside wires. Two impls:

- **`FrRepr(Fr)`** — plain BN254 scalar. Every op maps to native `Fr` arithmetic.
- **`FractionRepr`** — enum `Zero | Trivial(Fr) | Rational(Fr, Fr)`; propagates
  fractions through arithmetic. Mirrors halo2's `Assigned<F>`.

### Methods

| Method | Signature | Semantics |
|---|---|---|
| `zero` | `fn zero() -> Self` | additive identity |
| `one` | `fn one() -> Self` | multiplicative identity |
| `from_fr` | `fn from_fr(fr: Fr) -> Self` | lift a concrete Fr into R |
| `add` | `fn add(a: Self, b: Self) -> Self` | `a + b` |
| `sub` | `fn sub(a: Self, b: Self) -> Self` | `a - b` (defined as `add(a, neg(b))` in FractionRepr) |
| `mul` | `fn mul(a: Self, b: Self) -> Self` | `a * b` |
| `neg` | `fn neg(a: Self) -> Self` | `-a` |
| `invert` | `fn invert(a: Self) -> Self` | `1/a`. **FrRepr:** `Fr::invert().unwrap()`. **FractionRepr:** `Rational(1, a)` (O(1) swap). |
| `resolve` | `fn resolve(a: Self) -> Fr` | materialize to plain `Fr`. FractionRepr does `n * d.invert()` — inversion only pays here. |
| `is_field_zero` | `fn is_field_zero(a: Self) -> bool` | host-side branch: check the numerator |

### Dependencies

Leaf trait. Only depends on `Fr` arithmetic from
`halo2-lib/halo2-base/../halo2curves-axiom-*/src/bn256/fr.rs` (Montgomery form).

### Original inspiration

- `Assigned<F>` enum: `halo2/halo2_proofs/src/plonk/assigned.rs:10-19`
- Batch inversion of a whole advice column: `halo2/halo2_proofs/src/poly.rs::batch_invert_assigned` (line 341) — this is what makes FractionRepr's deferred invert practical in the real prover.

### Where used in tracegen

Only through the higher-level chip methods. Every arithmetic on a `Wire<R>` goes
through `R::add`/`sub`/`mul`. `R::invert` is called exclusively from
`GateChip::is_zero` (below).

---

## `GateChip<R>` (src/chip/gate.rs)

Concrete struct with all raw-Fr primitives. Not a trait — it's the "backing
gate" that both `RangeExt::gate()` and `BabyBearExt::gate()` return.

### Methods

| Method | Signature | Depends on | Original |
|---|---|---|---|
| `add(a, b)` | `R → R → R` | `R::add` | `halo2-lib/halo2-base/src/gates/flex_gate/mod.rs:159-169` |
| `sub(a, b)` | `R → R → R` | `R::sub` | `flex_gate/mod.rs:185-198` |
| `neg(a)` | `R → R` | `R::neg` | `flex_gate/mod.rs:236-242` |
| `mul(a, b)` | `R → R → R` | `R::mul` | `flex_gate/mod.rs:250-262` |
| `mul_add(a, b, c)` | `R → R → R → R` | `R::mul`, `R::add` | `flex_gate/mod.rs:271-283` |
| `sub_mul(a, b, c)` | `R → R → R → R` (returns `a - b*c`) | `R::mul`, `R::sub` | `flex_gate/mod.rs:215-229` |
| `mul_not(a, b)` | `(1-a)*b` | `R::one`, `R::sub`, `R::mul` | `flex_gate/mod.rs:291-303` |
| `sum(iter)` | `Σ` | `R::add` | `flex_gate/mod.rs:422-449` |
| `inner_product(a, b)` | `<a, b>` | `R::mul`, `R::add` | `flex_gate/mod.rs:968-1006` (`inner_product_simple`) |
| `is_zero(a)` | `R → R` (1 iff a=0) | `R::is_field_zero`, `R::invert` (side-effect only), `R::one`/`R::zero` | `flex_gate/mod.rs:816-837` |
| `is_equal(a, b)` | `R → R → R` | `sub`, `is_zero` | `flex_gate/mod.rs:843-851` |
| `not(a)` | `1 - a` | `R::one`, `R::sub` | `flex_gate/mod.rs:589-591` |
| `and(a, b)` | `a * b` | `R::mul` | `flex_gate/mod.rs:575-582` |
| `select(a, b, sel)` | `sel*(a-b) + b` | `sub`, `mul`, `add` | `flex_gate/mod.rs:1215-1241` |
| `idx_to_indicator(idx, len)` | `→ Vec<R>` | `is_zero`, `is_equal` | `flex_gate/mod.rs:690-727` |
| `select_by_indicator(a, ind)` | `→ R` | `R::is_field_zero` (host-side branch) | `flex_gate/mod.rs:736-757` |
| `num_to_bits(a, range_bits)` | `→ Vec<R>` | `R::resolve` (to Fr for byte extraction), `R::from_fr` | `flex_gate/mod.rs:1287-1319` |
| `assert_bit(x)` | no-op | — | `flex_gate/mod.rs:310-312` (was `x*(x-1)=0` gate row) |
| `assert_is_const(a, c)` | no-op | — | `flex_gate/mod.rs:342-348` (was copy constraint) |

### Key detail: `is_zero`

```rust
pub fn is_zero(&self, a: R) -> R {
    if R::is_field_zero(a) { R::one() }
    else {
        let inv_witness = R::invert(a);   // FrRepr pays here; FractionRepr is O(1)
        std::hint::black_box(inv_witness);
        R::zero()
    }
}
```

The `black_box` prevents the compiler from eliding the eager inversion in
`FrRepr` (the witness value is otherwise unused). This is the single point where
the two reprs diverge in per-call cost.

### Where used in tracegen

- `GateChip::mul`, `add`, `sub`, `mul_add`, `sum`, `inner_product`: called from
  every arithmetic operation in `BabyBearChip`, `RangeChip`, `Poseidon2State`,
  and the transcript decomposition.
- `is_zero`, `is_equal`: `transcript::constrain_base_baby_bear_decomposition`
  (via `range.is_less_than` → `gate.is_zero`), `range.is_less_than`,
  `gate.idx_to_indicator`.
- `select`: `verify/whir.rs::query_root_from_bits_assigned` (line 220),
  `verify/whir.rs::constrain_merkle_path` (lines 309-311).
- `num_to_bits`: `verify/whir.rs` inside the query-phase loop (line 453).
- `not`, `assert_is_const`: `transcript::constrain_base_baby_bear_decomposition`.

---

## `RangeExt` (src/chip/mod.rs) — `RangeChip<R>` implements it

Range-check + integer division primitives. Wraps a `GateChip<R>`.

### Methods

| Method | Signature | Depends on | Original |
|---|---|---|---|
| `gate() -> &GateChip<R>` | — | — | `range/mod.rs:606-608` |
| `lookup_bits() -> usize` | — | — | `range/mod.rs:611-613` |
| `range_check(a, range_bits)` | preserves limb-decomp + inner-product arithmetic | `R::resolve`, `R::from_fr`, `R::mul`, `R::add`, `GateChip::mul` | `range/mod.rs:540-599` (`_range_check`) |
| `check_less_than(a, b, num_bits)` | `a < b` constraint | `R::add`, `R::sub`, `R::from_fr`, `range_check` | `range/mod.rs:640-674` |
| `check_less_than_safe(a, b: u64)` | range-checks a to bit_length(b), then check_less_than | `range_check`, `check_less_than` | `range/mod.rs:214-220` |
| `check_big_less_than_safe(a, b: BigUint)` | same but for BigUint bound | `range_check`, `check_less_than` | `range/mod.rs:229-242` |
| `is_less_than(a, b, num_bits) -> R` | 1 iff a<b | `R::add`, `R::sub`, `R::from_fr`, `range_check`, `GateChip::is_zero` | `range/mod.rs:685-728` |
| `is_less_than_safe(a, b: u64) -> R` | | `range_check`, `is_less_than` | `range/mod.rs:264-275` |
| `is_big_less_than_safe(a, b: BigUint) -> R` | | `range_check`, `is_less_than` | `range/mod.rs:285-299` |
| `div_mod(a, b: BigUint, a_num_bits) -> (R, R)` | Euclidean division: BigUint host-side | `R::resolve`, `R::from_fr`, `check_big_less_than_safe` | `range/mod.rs:311-344` |

### Method-level dependencies (RangeExt only)

```
range_check ──┐
              ├─▶ (leaf: R::resolve, R::from_fr, R::mul, R::add, gate.mul)
check_less_than ─▶ range_check
check_less_than_safe / check_big_less_than_safe ─▶ range_check + check_less_than
is_less_than ─▶ range_check + gate.is_zero  ← this is why `is_less_than` is where
                                              the invert cost hits
is_less_than_safe / is_big_less_than_safe ─▶ range_check + is_less_than
div_mod ─▶ check_big_less_than_safe (×2)
```

### Where used in tracegen

- `range_check`: `BabyBearChip::load_witness` (line 108),
  `BabyBearChip::signed_div_mod` (line 84 — every `reduce`).
- `check_less_than_safe`: `BabyBearChip::load_reduced_witness` (line 114),
  `transcript::constrain_base_baby_bear_decomposition` (line 90).
- `check_big_less_than_safe`: `BabyBearChip::signed_div_mod` (line 86, for the
  remainder), `RangeChip::div_mod` (twice).
- `is_big_less_than_safe`: `transcript::constrain_base_baby_bear_decomposition`
  (line 94 — the top-quotient bound check).
- `is_less_than`: `transcript::constrain_base_baby_bear_decomposition` (line 108
  — the lower-part boundary check).
- `div_mod`: `TranscriptChip::sample_bits` (line 251 — sample low bits of a
  challenge).
- `gate()`: pervasive (every chip that uses `RangeChip` needs to reach `GateChip`).

---

## `BabyBearExt` (src/chip/mod.rs) — `BabyBearChip<R>` implements it

BabyBear-in-Fr with lazy reduction. Wire is `Wire<R> = { value: R, max_bits: u32 }`.

Constants: `BABY_BEAR_MODULUS_U64 = 2013265921`, `BABYBEAR_MAX_BITS = 31`,
`RESERVED_HIGH_BITS = 2`, `FR_CAPACITY = 253`.

### Methods

| Method | Signature | Depends on | Original |
|---|---|---|---|
| `range() -> &Range` | — | — | `field/baby_bear/base.rs:105-107` |
| `gate() -> &GateChip<R>` (default) | — | `range().gate()` | `field/baby_bear/base.rs:101-103` |
| `load_witness(BabyBear) -> Wire<R>` | `range_check` to 31 bits | `range.range_check` | `base.rs:115-123` |
| `load_reduced_witness(BabyBear) -> ReducedWire<R>` | `check_less_than_safe(_, MOD)` | `range.check_less_than_safe` | `base.rs:126-139` |
| `load_constant(BabyBear) -> Wire<R>` | cached | `R::from_fr` | `base.rs:141-159` |
| `load_reduced_constant(BabyBear) -> ReducedWire<R>` | tag-only wrapping | `load_constant` | `base.rs:162-170` |
| `reduce(a) -> Wire<R>` | canonicalize | `signed_div_mod` (private) | `base.rs:172-183` |
| `reduce_max_bits(a) -> Wire<R>` | reduce iff `max_bits > 31` | `reduce` | `base.rs:187-194` |
| `add(a, b) -> Wire<R>` | max_bits-aware Fr add | `reduce` (guard), `gate.add` | `base.rs:196-214` |
| `sub(a, b) -> Wire<R>` | max_bits-aware Fr sub | `reduce` (guard), `gate.sub` | `base.rs:227-247` |
| `mul(a, b) -> Wire<R>` | max_bits-aware Fr mul | `reduce` (guard), `gate.mul` | `base.rs:249-271` |
| `mul_add(a, b, c) -> Wire<R>` | | `reduce` (guard), `gate.mul_add` | `base.rs:273-302` |
| `neg(a) -> Wire<R>` | | `gate.neg` | `base.rs:216-225` |
| `div(a, b) -> Wire<R>` | non-zero constraint + witness inv | `load_witness`, `load_constant`, `mul`, `assert_equal`, `assert_zero`, `gate.sub_mul` | `base.rs:304-341` — uses **BabyBear** (31-bit) inversion, not Fr |
| `special_inner_product(a, b, s) -> Wire<R>` | ext-mul helper | `reduce` (guard), `gate.mul_add` | `base.rs:345-403` |
| `zero() / one()` | consts | `load_constant` | `base.rs:459-467` |
| `mul_const(a, c) -> Wire<R>` | | `load_constant`, `mul` | `base.rs:469-478` |
| `square(a) / pow_power_of_two(a, n)` | | `mul`, `square` | `base.rs:480-497` |
| `assert_zero(a)` | no-op | — | `base.rs:418-450` (was BigUint div + range_check) |
| `assert_equal(a, b)` | no-op | — | `base.rs:452-457` |
| `select(cond: R, a, b) -> Wire<R>` | | `gate.select` | `base.rs:405-416` |

### Private helper

- `signed_div_mod(a: R, a_num_bits) -> (R, R)`: BigUint Euclidean divide by
  `BABY_BEAR_MODULUS_U64`; range-checks the quotient. Original: `base.rs:518-624`.

### Dependency shape

Every arithmetic method has the same shape: (1) `max_bits` guard → maybe
`reduce`, (2) delegate to a single `GateChip` op. That means every `BabyBearExt`
arithmetic bottoms out in at most 1 `R::add`/`R::sub`/`R::mul` plus zero-or-more
`signed_div_mod` calls (each of which triggers a `range_check` = O(limbs)
Fr muls). This is why `reduce_max_bits` is called explicitly in hot spots
(WHIR fold, batch-constraint pow accumulation) — to amortize the guard cost.

### Where used in tracegen

- `load_reduced_witness`: `load_gkr_proof_wire`, `load_batch_constraint_proof_wire`,
  `load_stacking_proof_wire`, `load_whir_proof_wire` (every `ReducedBabyBearWire`
  from the proof).
- `mul`, `add`, `sub`, `mul_add`, `reduce_max_bits`: used indirectly through
  `BabyBearExt4Chip` (which delegates all coefficient-wise ops). Direct calls
  come from `verify/whir.rs::query_root_from_bits_assigned` (base-field
  multiply chain) and `binary_k_fold_assigned` (base fold twiddles).
- `div`: `verify/whir.rs::invert_base_assigned` — 1 call per WHIR query point
  per query.
- `special_inner_product`: exclusively from `BabyBearExt4Chip::mul` (7 times per
  extension mul).

### Original

Every method mirrors `openvm/crates/static-verifier/src/field/baby_bear/base.rs`.

---

## `BabyBearExtInst` (src/chip/mod.rs) — `BabyBearExt4Chip<R>` implements it

Quartic extension over BabyBear (irreducible `x^4 - W`).
`ExtWire<R> = [Wire<R>; 4]`.

### Methods

| Method | Signature | Depends on | Original |
|---|---|---|---|
| `base() -> &Base` | — | — | `field/baby_bear/extension.rs:317-319` |
| `range()` (default) | — | `base().range()` | `extension.rs:321-323` |
| `load_witness(BabyBearExt4) -> ExtWire<R>` | 4× base | `base.load_witness` | `extension.rs:102-106` |
| `load_reduced_witness / load_constant / load_reduced_constant` | 4× base | `base.load_*` | `extension.rs:109-139` |
| `add(a, b) / sub(a, b) / neg(a)` | coefficient-wise | `base.add` / `.sub` / `.neg` | `extension.rs:140-183` |
| `scalar_mul(a: ExtWire, b: Wire) -> ExtWire` | mul each coeff by base | `base.mul` (×4) | `extension.rs:185-199` |
| `scalar_mul_add(a, b, c) -> ExtWire` | fused: `base.mul_add` (×4) | `base.mul_add` (×4) | `extension.rs:201-219` |
| `select(cond: R, a, b) -> ExtWire` | | `base.select` (×4) | `extension.rs:221-237` |
| `mul(a, b) -> ExtWire` | schoolbook + w-reduction | `base.special_inner_product` (×7) + `base.mul_add` (×3) + `base.load_constant` | `extension.rs:253-277` |
| `div(a, b) -> ExtWire` | witness inverse + verify | `load_witness`, `mul`, `assert_equal` — uses **BabyBearExt4** (native quartic) inversion | `extension.rs:279-304` |
| `reduce_max_bits(a) -> ExtWire` | per-coeff | `base.reduce_max_bits` (×4) | `extension.rs:306-315` |
| `zero() / from_base_const(c) / from_base_var(w)` | | `base.load_constant` | `extension.rs:325-345` |
| `mul_base_const(a, c) -> ExtWire` | | `base.load_constant`, `scalar_mul` | `extension.rs:347-355` |
| `square / pow_power_of_two` | | `mul` | `extension.rs:357-372` |
| `assert_zero / assert_equal` | no-ops | — | `extension.rs:239-251` |

### Cost of `mul`

`BabyBearExt4Chip::mul` is *the* hot method in the arithonly path. Per call:

- 7 × `special_inner_product` on 4-limb slices — total ~13 base `mul_add`s.
- 3 × `base.mul_add` for the w-reduction (`coeffs[i-4] += w * coeffs[i]`, i∈{4,5,6}).
- Implicit `reduce_max_bits` on operands via the guard chain.

**Net:** ≥16 `R::mul` + several `R::add` per extension mul. In WHIR + batch
constraints + stacked reduction this dominates the arithmetic budget.

### Where used in tracegen

Every ext-arithmetic call site under `src/verify/`:

- `verify/batch_constraints.rs`: GKR sumcheck (`interpolate_cubic_at_0123_assigned`,
  `interpolate_linear_at_01_assigned`), `eval_eq_mle_assigned`, `eval_eq_prism_assigned`,
  `eval_lagrange_on_integer_grid`, `progression_exp_2_assigned`,
  `eval_symbolic_nodes_assigned`, the eq/eq_sharp Ns loop, the interactions loop.
- `verify/stacked_reduction.rs`: `lambda_sqr_powers`, `t_claims` batching,
  `interpolate_quadratic_at_012_assigned`, `derived_q_coeffs` accumulation.
- `verify/whir.rs`: `mu_pows` accumulation, sumcheck poly evals, gamma
  accumulation, `eval_mobius_eq_mle_assigned`, `eval_mle_evals_at_point_assigned`,
  `binary_k_fold_assigned` (per query per WHIR round), the final consistency
  loop.

### Original

`openvm/crates/static-verifier/src/field/baby_bear/extension.rs`

---

## Cross-cutting: transcript & Poseidon2

Not traits themselves, but heavy users of the traits.

### `TranscriptChip<B: BabyBearExt>` (src/transcript.rs)

Wraps a base chip. Sponge state is `[B::R; POSEIDON2_WIDTH]`.

- `observe(&ReducedWire<B::R>)` → buffers, calls `pack_base_2_31_cells` → `sponge_absorb`.
- `observe_ext(&ReducedExtWire<B::R>)` → 4× `observe`.
- `observe_commit(&DigestWire)` → direct `sponge_absorb` on Fr digest words via `B::R::from_fr`.
- `sample() -> Wire<B::R>` → `sponge_squeeze` + `decompose_bn254_to_base_baby_bear_digits`.
  - `decompose_...` calls: `range.check_less_than_safe` (×5), `range.is_big_less_than_safe`,
    `gate.inner_product`, `gate.mul_add`, `gate.is_equal`, `range.range_check`,
    `range.is_less_than`, `gate.not`, `gate.mul`.
- `sample_ext() -> ExtWire<B::R>` → 4× `sample`.
- `sample_bits(bits) -> B::R` → `sample` + `range.div_mod`.
- `check_witness(bits, &witness)` → `observe` + `sample_bits` + `gate.assert_is_const`.

Original: `openvm/crates/static-verifier/src/transcript/mod.rs`

### `Poseidon2State<R, T>` (src/hash/poseidon2.rs)

- `permutation`: `matmul_external` → (rounds_f/2 × `add_rc` + `sbox` + `matmul_external`) →
  (rounds_p × `s[0] += rc; s[0] = x^5(s[0]); matmul_internal`) →
  (rounds_f/2 × `add_rc` + `sbox` + `matmul_external`).
- `x_power5(x)` = `x*x, x2*x2, x*x4` → 3 `R::mul`.
- `matmul_external` (T=3): `sum = s[0]+s[1]+s[2]; s[i] += sum` → 3 `R::add` + 3 `R::add`.
- `matmul_internal(diag)`: `sum = Σ s; s[i] = s[i]*diag[i] + sum` → T `R::mul` + T `R::add`.

Original: `openvm/crates/static-verifier/src/hash/poseidon2.rs`

**Number of Fr ops per Poseidon2 permutation (T=3):** ~250 `R::mul` +
~200 `R::add`. Called ~200 times per fibonacci-1000 root proof (transcript
squeezes + WHIR Merkle path compressions).

---

## Tracegen call graph (top-down)

```
constrained_verify (verify/full_pipeline.rs)
├─ observe_preamble
│    └─ transcript.observe_commit / observe / baby_bear.load_reduced_constant
│
├─ constrain_batch_constraints_verification (verify/batch_constraints.rs)
│    ├─ transcript.check_witness / sample_ext / observe_ext
│    ├─ ext_chip.mul / add / sub / reduce_max_bits         ← main arithmetic
│    ├─ ext_chip.mul_base_const                            ← BabyBear × ExtWire scalar
│    ├─ ext_chip.assert_zero / assert_equal                ← no-op
│    ├─ eval_eq_mle_assigned / eval_eq_uni_assigned / eval_eq_prism_assigned
│    ├─ eval_symbolic_nodes_assigned (AIR constraint DAG)
│    └─ eval_lagrange_on_integer_grid (sumcheck consistency)
│
├─ constrain_stacked_reduction (verify/stacked_reduction.rs)
│    ├─ column_openings_by_rot_assigned
│    ├─ transcript.sample_ext / observe_ext
│    ├─ interpolate_quadratic_at_012_assigned
│    └─ eval_eq_prism_assigned / eval_rot_kernel_prism_assigned / eval_eq_mle_binary_assigned
│
├─ u_cube (ext_chip.square + reduce_max_bits, l_skip times)
│
└─ constrain_whir_verification (verify/whir.rs)
     ├─ transcript.check_witness / sample_ext / sample_bits / observe_commit
     ├─ mu_pows accumulation
     ├─ per-round sumcheck: interpolate_quadratic_at_012_assigned
     ├─ per-query:
     │    ├─ transcript.sample_bits → gate.num_to_bits
     │    ├─ query_root_from_bits_assigned (base gate.select + base.mul)
     │    ├─ constrain_merkle_path
     │    │     ├─ hash_babybear_slice_to_digest        (Poseidon2 T=3)
     │    │     ├─ tree_compress_assigned_digests       (Poseidon2 T=2)
     │    │     └─ compress_bn254_digests + gate.select (Merkle step)
     │    └─ binary_k_fold_assigned
     │          ├─ invert_base_assigned                  ← base.div (BabyBear inv)
     │          └─ base.mul_const / ext_chip.scalar_mul_add / ext_chip.mul
     ├─ eval_mobius_eq_mle_assigned / eval_mle_evals_at_point_assigned
     ├─ horner_eval_ext_poly_assigned / horner_eval_ext_poly_f_assigned
     └─ ext_chip.assert_equal (final)
```

---

## Which methods pay the invert cost?

`R::invert` is called from exactly one site: `GateChip::is_zero`. Every path
that reaches `is_zero` pays. In FrRepr that's a real `Fr::invert()`; in
FractionRepr it's a match + swap.

Call sites reaching `is_zero`:

- `RangeExt::is_less_than` — 1 per call.
- `RangeExt::is_less_than_safe` / `is_big_less_than_safe` — 1 per call.
- `GateChip::is_equal` — 1 per call.
- `GateChip::idx_to_indicator(idx, len)` — `len` calls (1 `is_zero` + `len-1` `is_equal`).

Places these are actually invoked in the arithonly pipeline (fibonacci-1000):

- **Transcript sample decomposition** (per squeezed challenge): 1 `is_big_less_than_safe`
  + 1 `is_equal` + 1 `is_less_than` = **3 `is_zero`s per challenge**.
  Number of challenges ≈ dominant contributor to invert count.
- WHIR query-phase `num_to_bits` does **not** hit `is_zero` (it uses `R::resolve`
  + bit extraction from raw bytes).
- No `idx_to_indicator` calls in the current pipeline.

That gives ~200-500 `is_zero` calls per proof — a modest count. Which matches
the profile: FrRepr's inversion tax is small compared to the arithmetic body,
which is why FractionRepr's per-op enum overhead wins net-worse despite its
zero-cost invert.
