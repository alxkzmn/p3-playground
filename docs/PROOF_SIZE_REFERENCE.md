# HyperPlonk Keccak Proof Size Reference (final)

Conventions:

- **(M)** = measured from `keccak_profile` binary. **(E)** = estimated from model.
- Where measured and estimated disagree, measured values win.
- Formulas are first-order approximations unless noted; use measured baselines to calibrate.

Scope:

- Target system: HyperPlonk + WHIR PCS.
- Circuit family: Keccak-256 (large, bit-heavy AIR).
- Goal: reduce **whole proof size** (native + calldata) below 128 KB for 1–2 KB inputs.
- Protocol-preserving path first; protocol redesign is a later track.

---

## 1. Proof anatomy

```rust
struct Proof<C> {
    log_bs: Vec<usize>,          // log₂(height) per AIR — 8 bytes each
    commitment: Com<C>,          // single Merkle root — 32 bytes (constant)
    piop: PiopProof<Challenge>,  // ← ~82% of proof
    pcs: Vec<WhirProof>,         // ← ~17% of proof (WHIR opening)
}

struct PiopProof<Challenge> {
    fractional_sum: FractionalSumProof<Challenge>,   // LogUp tree
    air: AirProof<Challenge>,                        // sumcheck + evals
}

struct AirProof<Challenge> {
    univariate_skips: Vec<AirUnivariateSkipProof>,        // tiny
    regular: BatchSumcheckProof<Challenge>,                // ← THE BIG ONE
    univariate_eval_check: BatchSumcheckProof<Challenge>,  // tiny
}

struct BatchSumcheckProof<Challenge> {
    compressed_round_polys: Vec<CompressedRoundPoly<Challenge>>,  // ~0.6 KB
    evals: Vec<Vec<Challenge>>,  // ← ~99% of air.regular
}
```

**Challenge** = `BinomialExtensionField<KoalaBear, 4>` = 4 × 4 bytes = **16 bytes**.

---

## 2. What dominates

### 2.1 The dominant term

```
air.regular.evals ≈ 2 × Σ(width_i) × sizeof(Challenge)
```

Every column costs **32 bytes** in the proof (16 for local-row eval + 16 for next-row eval).
This is linear in total AIR width and is the **single largest proof component**.

### 2.2 The second term (when interactions exist)

```
fractional_sum ≈ f(interaction_count, layer_count, FS_ARITY, Challenge)
```

This is not a clean closed-form — it depends on trace packing, layer structure,
and serialization overhead. As an order-of-magnitude approximation:

```
fractional_sum ≈ interaction_count × log₂(max_height) × FS_ARITY × 2 × 16
               ≈ interaction_count × ~576 bytes       (approximate)
```

Empirically:

- 68 interactions (u16 XOR lookup): **~25–40 KB** (grows with input size / height).
- 0 interactions: **~0 KB** (trivial serialized object, measured as 16 bytes).

Always use measured values to calibrate; the formula above is a planning estimate.

### 2.3 Everything else

| Component                   | Scaling         |   Typical | Notes                                |
| --------------------------- | --------------- | --------: | ------------------------------------ |
| `commitment`                | constant        |      32 B | Single Merkle root for all AIRs      |
| `air.regular.round_polys`   | HEIGHT × DEGREE |    ~576 B | `log₂(max_height) × (degree+1) × 16` |
| `air.univariate_skips`      | skip rounds     |     ~56 B | Currently near-zero                  |
| `air.univariate_eval_check` | skip rounds     |     ~32 B | Currently near-zero                  |
| `pcs` (WHIR)                | log(poly_size)  | ~22–28 KB | Weakly dependent on width (see §4)   |

---

## 3. Measured reference points

All measured from `keccak_profile` binary. These are the ground truth for calibration.

### A) `input_size=128`, ByteSpongeWithXorLookup

| Field                     |       Value |
| ------------------------- | ----------: |
| `native_proof_size_bytes` | **141,295** |
| `piop`                    |     119,536 |
| `fractional_sum`          |      24,720 |
| AIR[0] width              |        2909 |
| AIR[0] interaction_count  |          68 |
| AIR[1] width              |          34 |
| AIR[1] interaction_count  |           1 |

### B) `input_size=128`, SingleBlockNoLookup

| Field                     |        Value |
| ------------------------- | -----------: |
| `native_proof_size_bytes` | **~113,759** |
| `piop`                    |      ~93,704 |
| `fractional_sum`          |           16 |
| AIR[0] width              |         2909 |
| AIR[0] interaction_count  |            0 |

### C) `input_size=1024`, ByteSpongeWithXorLookup

| Field                                |       Value |
| ------------------------------------ | ----------: |
| `native_proof_size_bytes`            | **164,061** |
| `piop`                               |     135,168 |
| `fractional_sum`                     |      39,936 |
| `air.regular`                        |      95,144 |
| `air.regular.evals` (computed)       |     ~94,176 |
| `air.regular.round_polys` (residual) |        ~968 |
| AIR[0] width                         |        2909 |
| AIR[0] interaction_count             |          68 |
| AIR[1] width                         |          34 |
| AIR[1] interaction_count             |           1 |
| WHIR PCS                             |     ~28,517 |

### Cross-check: predicted vs measured for C

```
evals = 2 × (2909 + 34) × 16 = 94,176   ← predicted
air.regular =                   95,144   ← measured
residual = 95,144 − 94,176 =      968   ← round_polys + bincode overhead
```

The evals formula tracks reality to within **~1%**. The residual (968 B) is close
to the theoretical 576 B for round polys; the ~400 B gap is serialization overhead
(Vec lengths, enum tags, etc.).

### Key takeaways from measured data

1. Removing interactions (A→B) saves **~27 KB** at input_size=128.
2. `fractional_sum` grows with input size: 24.7 KB @128 → 39.9 KB @1024.
3. `air.regular.evals` dominates once `fractional_sum` is gone (~93 KB @128 no-lookup).
4. `SingleBlockNoLookup` only works for ≤135 bytes (single Keccak block).

---

## 4. WHIR PCS internals

### Why WHIR is weakly dependent on width

All trace columns from all AIRs are concatenated, then each matrix is
**padded to power-of-2 width** and laid out into one flat multilinear polynomial:

```
polynomial_size = Σ (width_i.next_power_of_two() × height_i)
num_variables   = ceil(log₂(polynomial_size))
```

Current layout (ByteSponge + XorLookup):

- AIR[0]: 2909 → pad 4096 × 256 = 1,048,576
- AIR[1]: 34 → pad 64 × 512 = 32,768
- Total: 1,081,344 → **~21 variables**

Single AIR at width 2909:

- 2909 → pad 4096 × 256 = 1,048,576 → **20 variables**

When opening, column values are collapsed into a **random linear combination**
(one scalar claim per query point). WHIR then proves these scalar claims.
The proof cost depends on `num_variables`, not directly on how many columns were
combined. However, width affects `num_variables` through the power-of-2 padding,
so the dependence is **logarithmic, not zero**.

### WHIR sub-component breakdown (28,509 bytes measured)

| Sub-component                    |      Bytes |  % of PCS |
| -------------------------------- | ---------: | --------: |
| `initial_commitment`             |         32 |      0.1% |
| `initial_ood_answers`            |         40 |      0.1% |
| `initial_sumcheck`               |        160 |      0.6% |
| **`rounds` (3 FRI-like rounds)** | **23,205** | **81.4%** |
| `final_poly`                     |        521 |      1.8% |
| `final_pow_witness`              |          4 |      0.0% |
| `final_query_batch`              |      4,370 |     15.3% |
| `final_sumcheck`                 |        177 |      0.6% |

WHIR `rounds` dominate PCS cost — these are Merkle authentication paths whose
size scales with `num_variables` and the folding/query parameters.

### Power-of-2 padding thresholds

| Condition    | Padded width | PCS variables (height=256) | Approx WHIR cost |
| ------------ | -----------: | -------------------------: | ---------------: |
| Width > 2048 |         4096 |                         20 |           ~28 KB |
| Width ≤ 2048 |         2048 |                         19 |           ~25 KB |
| Width ≤ 1024 |         1024 |                         18 |           ~22 KB |

Getting below 2048 columns would save ~3 KB in WHIR. But keccak's practical floor
is ~2194 columns (see §5), so crossing the 2048 threshold is extremely unlikely
without changing the hash function.

---

## 5. Keccak AIR column anatomy

### P3 keccak-air: 2633 permutation columns

| Group             | Shape        |     Cols |     % | Role                            |   Max constraint degree |
| ----------------- | ------------ | -------: | ----: | ------------------------------- | ----------------------: |
| `a_prime`         | `[5][5][64]` | **1600** | 60.8% | Core witness: post-θ state bits |                2 (bool) |
| `c`               | `[5][64]`    |      320 | 12.2% | θ column parities               |        3 (parity cubic) |
| `c_prime`         | `[5][64]`    |      320 | 12.2% | Rotated parities                |     3 (xor3 definition) |
| `a`               | `[5][5][4]`  |      100 |  3.8% | Packed u16 state (θ output)     |      3 (reconstruction) |
| `a_prime_prime`   | `[5][5][4]`  |      100 |  3.8% | Packed χ output                 |          3 (chi + pack) |
| `a_pp_0_0_bits`   | `[64]`       |       64 |  2.4% | ι bit decomposition             | 2 (bool + linear recon) |
| `a_ppp_0_0_limbs` | `[4]`        |        4 |  0.2% | ι output (lane 0,0)             |         2 (xor with RC) |
| `step_flags`      | `[24]`       |       24 |  0.9% | One-hot round selector          |            2 (rotation) |
| `preimage`        | `[5][5][4]`  |      100 |  3.8% | Permutation input (sponge)      |       2 (held constant) |
| `export`          | scalar       |        1 |  0.0% | Sponge export flag              |                2 (bool) |

### ByteSponge wrapper: +276 sponge columns

| Field                  | Cols | Removable?               |
| ---------------------- | ---: | ------------------------ |
| `hash_end`             |    1 | No                       |
| `seen_end`             |    1 | No                       |
| `active`               |    1 | Yes (= `1 − seen_end`)   |
| `is_new_start`         |    1 | Yes (= `is_first_row()`) |
| `block_bytes[136]`     |  136 | No — message witness     |
| `is_padding_byte[136]` |  136 | No — padding enforcement |

**Total current width: 2633 + 276 = 2909.**

### Dependency graph and removability

```
a_prime (1600) ─── CORE WITNESS (non-negotiable)
    │
    ├──→ c (320) = XOR5(a_prime columns)            NON-NEGOTIABLE
    │       Removing → degree 30+ cascade
    │
    ├──→ c_prime (320) = rotated parities from c    REMOVABLE @ degree 6
    │
    ├──→ B[x,y,z] = ROT(a_prime)                   FREE (index remap only)
    │       └──→ chi: XOR(B, ANDN(B,B)) = degree 3
    │               └──→ a_prime_prime (100)         REMOVABLE @ degree 5
    │
    ├──→ a (100) = packed theta output               REMOVABLE @ degree 5
    │
    ├──→ a_pp_0_0_bits (64) = chi bit decomp         REMOVABLE @ degree 6
    │
    └──→ a_ppp_0_0_limbs (4) = iota output           REMOVABLE @ degree 4
```

### Column removal budget by max degree

|     Max degree | What's removed               | Cols saved | Remaining width | Evals saved |
| -------------: | ---------------------------- | ---------: | --------------: | ----------: |
| 3 (P3 default) | nothing                      |          0 |            2909 |        0 KB |
|              4 | `a_ppp_0_0_limbs`            |          4 |            2905 |      0.1 KB |
|              5 | + `a`, `a_prime_prime`       |        204 |            2705 |      6.5 KB |
|              6 | + `a_pp_0_0_bits`, `c_prime` |        588 |            2321 |     18.8 KB |
|             9+ | Aggressive reformulation     |       ~800 |           ~2100 |    ~25.6 KB |

Note: these are practical bounds from the P3 column structure, not formal
impossibility proofs. A radically different Keccak AIR decomposition might
find slightly different trade-offs, but the `a_prime` + `c` floor is robust.

### Practical column floor

`a_prime` (1600) + `c` (320) = **1920 columns**.
Plus sponge (274 non-removable) = **~2194 minimum**.
At `2 × 2194 × 16` = **~70 KB** evals floor for any Keccak AIR on this protocol.

---

## 6. Preprocessed / fixed columns

### Current status: NOT SUPPORTED

`Entry::Preprocessed` exists in `SymbolicVariable` but is dead code.
`VerifyingKey` stores no commitments. `ProvingKey` wraps `VerifyingKey` only.

### What IS zero-cost today

`is_first_row`, `is_last_row`, `is_transition` are computed analytically from the
sumcheck challenge point — **zero proof bytes**:

```
IsFirstRow(c).fix_var(z_i) → c × (1 − z_i)
IsLastRow(c).fix_var(z_i)  → c × z_i
```

### Would preprocessed columns help?

Moving `step_flags[24]` to preprocessed trace would save 24 × 32 = **768 bytes**.
Engineering cost: changes across keygen, prover, verifier, symbolic builder, all
folder structs. **Poor ROI for <1 KB savings.**

---

## 7. Interaction count impact

Interactions use LogUp via fractional-sum binary trees (`FS_ARITY = 2`).

|       Interaction count | Mode                            | Measured fractional sum |
| ----------------------: | ------------------------------- | ----------------------: |
| 272 (V1 byte-level XOR) | — (abandoned)                   |         ~157 KB **(E)** |
|   68 (V2 u16-level XOR) | ByteSpongeWithXorLookup         |        25–40 KB **(M)** |
|                       0 | SingleBlockNoLookup / algebraic |            16 B **(M)** |

The fractional-sum cost is the **steepest unit-cost item** in the entire proof.
Dropping to zero interactions is the single highest-ROI move.

---

## 8. Degree vs prover cost trade-off

Higher constraint degree affects round polynomial size and prover work:

| Metric                             | Degree 3 | Degree 6 | Degree 9 |
| ---------------------------------- | -------: | -------: | -------: |
| Round poly coefficients per round  |        4 |        7 |       10 |
| Round poly bytes (9 rounds)        |    576 B |  1,008 B |  1,440 B |
| Prover constraint evals per round  |        4 |        7 |       10 |
| Prover slowdown (sumcheck portion) |       1× |   ~1.75× |    ~2.5× |
| Impact on `evals`                  |     none |     none |     none |
| Impact on WHIR                     |     none |     none |     none |

**Round poly overhead is negligible** — even at degree 9 it's under 1.5 KB.
The real cost is prover time. Degree 5–6 is the sweet spot: ~1 KB extra proof
bytes, moderate prover slowdown, significant column savings (200–588 columns).

---

## 9. Strategy comparison

All for keccak-256, Binomial4, 100-bit security.

### input_size = 128

| Strategy                              |   Width |  Evals | Frac.Sum |   WHIR | **Native total** |
| ------------------------------------- | ------: | -----: | -------: | -----: | ---------------: |
| ByteSponge+XorLookup **(M)**          | 2909+34 | ~94 KB |  24.7 KB | ~22 KB |       **141 KB** |
| SingleBlockNoLookup **(M)**           |    2909 | ~93 KB |    ~0 KB | ~21 KB |      **~114 KB** |
| Algebraic XOR, P3 **(E)**             |    2909 | ~93 KB |        0 | ~21 KB |      **~115 KB** |
| Custom deg 6, no interactions **(E)** |   ~2321 | ~74 KB |        0 | ~21 KB |       **~96 KB** |

### input_size = 1024

| Strategy                              |   Width |  Evals | Frac.Sum |   WHIR | **Native total** |
| ------------------------------------- | ------: | -----: | -------: | -----: | ---------------: |
| ByteSponge+XorLookup **(M)**          | 2909+34 | ~94 KB |  39.9 KB | ~28 KB |       **164 KB** |
| Algebraic XOR, P3 **(E)**             |    2909 | ~93 KB |        0 | ~26 KB |      **~120 KB** |
| Custom deg 5, no interactions **(E)** |   ~2705 | ~87 KB |        0 | ~26 KB |      **~114 KB** |
| Custom deg 6, no interactions **(E)** |   ~2321 | ~74 KB |        0 | ~26 KB |      **~101 KB** |

Estimates should be validated with profiling runs once implemented.

---

## 10. Levers ranked by ROI

| #     | Lever                                                           |       Savings | Difficulty      | Protocol change?   | Status                         |
| ----- | --------------------------------------------------------------- | ------------: | --------------- | ------------------ | ------------------------------ |
| **1** | **Kill all interactions** (algebraic absorb XOR)                | **~25–40 KB** | Medium          | No                 | Proposed; not implemented      |
| **2** | **Remove intermediate columns** (custom keccak AIR, degree 5–6) |       6–19 KB | High            | No (IOP unchanged) | Requires forking P3 keccak-air |
| **3** | Tune WHIR parameters                                            |        2–5 KB | Low             | No                 | Secondary                      |
| —     | Smaller extension field                                         |        ~47 KB | Infeasible      | N/A                | Violates 100-bit security      |
| —     | Different hash function                                         |       ~60+ KB | Out of scope    | N/A                | Not aligned with Keccak goals  |
| —     | Binary-field protocol stack                                     |       ~60+ KB | Major migration | Yes                | Long-term research             |
| —     | Fractional-sum protocol redesign                                |      Variable | Very high       | Yes                | Long-term research             |

---

## 11. What is NOT a practical lever

Included so future decisions don't re-explore dead ends:

- **Switching hash** (Poseidon, etc.): ~200 columns vs ~2900 — dramatic savings, but
  not aligned with Keccak benchmark goals.
- **Binary-field protocol** (Binius-style): eliminates bit-decomposition columns entirely,
  but requires a full protocol migration.
- **HyperPlonk protocol redesign** (new fractional-sum argument, batched evals):
  could reduce `evals` or change the 2× local+next model, but high effort/risk.
- **Preprocessed `step_flags`**: <1 KB savings for significant engineering.
- **Smaller extension degree**: violates 100-bit security target.

---

## 12. Roadmap

### Phase A — done

- `SingleBlockNoLookup` mode for `input_size ≤ 135`.
- Confirmed `interaction_count = 0` eliminates fractional-sum overhead.
- Profiled all three modes at multiple input sizes.

### Phase B — next (highest ROI)

- Add algebraic absorb mode (tentative name `AlgebraicXor` or `NoLookupAnyInput`):
  - Single AIR, width 2909 (reuses P3 keccak-air).
  - Zero interactions.
  - Cross-block absorb XOR enforced via constraints on existing `a_prime`, `c_prime`,
    `a_prime_prime_0_0_bits` columns.
- Keep `ByteSpongeWithXorLookup` as fallback / A-B comparator.

### Phase C — measure and gate

- Profile at `input_size = 128, 1024, 2048`.
- Gate on acceptance criteria (see §13).

### Phase D — optional: custom narrow AIR

- Only if Phase C doesn't clear the bar with enough margin.
- Fork keccak-air, raise degree to 5–6, remove `a`, `a_prime_prime`, `c_prime`,
  `a_pp_0_0_bits`.
- Expected additional savings: 6–19 KB.

---

## 13. Acceptance gates

For each profiled `input_size` (128, 1024, 2048):

| #   | Gate                                  | Threshold                                      |
| --- | ------------------------------------- | ---------------------------------------------- |
| 1   | `interaction_count` for all AIR metas | `== 0`                                         |
| 2   | `fractional_sum` serialized size      | `≤ 64 bytes`                                   |
| 3   | `native_proof_size_bytes`             | `< 131,072` (128 KB) for 1–2 KB inputs         |
| 4   | Correctness tests                     | All keccak + blob codec tests green            |
| 5   | Prove-time regression                 | `< 2×` vs current ByteSponge mode (documented) |

If gate 3 fails after Phase B but the others pass, proceed to Phase D (custom AIR).

---

## 14. Sanity-check formulas

### 14.1 `air.regular.evals` prediction

```
evals_bytes ≈ 2 × (Σ width_i) × 16
```

Moving from 2 AIRs (2909 + 34 = 2943) to 1 AIR (2909):

- Width savings: `2 × 34 × 16 = 1,088` bytes.
- Plus elimination of `fractional_sum` if interactions → 0: **~25–40 KB**.

Cross-check: for measurement C (width 2943), predicted evals = 94,176 B,
measured `air.regular` = 95,144 B. Residual ~968 B from round_polys + serialization.
Formula accuracy: **~99%**.

### 14.2 Fractional-sum diagnostic

If `fractional_sum` serialized size > 100 bytes and you expected zero interactions:

- **bug** — some interaction is still being pushed. Check `push_send` / `push_receive`
  calls and `enable_lookup_interactions` flag.

### 14.3 Mode wiring

For any mode:

- `public_inputs.len() == proof.log_bs.len()` — required for blob encoding.
- AIR count, widths, and interaction counts must match mode expectations.
- `fractional_sum` layers should be empty when `interaction_count = 0` across all AIRs.

### 14.4 WHIR polynomial size

```
pcs_poly_size = Σ (width_i.next_power_of_two() × height_i)
num_variables = ceil(log₂(pcs_poly_size))
```

Check that `num_variables` matches expectations. A jump from 20 → 21 variables
means the concatenated polynomial doubled (e.g., height doubled or a second AIR
was added with significant padded width).

---

## 15. Summary

The proof is **~82% PIOP, ~17% WHIR**. Within the PIOP, the dominant cost is
`air.regular.evals ≈ 2 × width × 16` bytes per column. The secondary cost is
`fractional_sum`, which scales with interaction count and trace height.

The fastest path to sub-128 KB:

1. Eliminate all interactions (algebraic absorb XOR) → save ~25–40 KB → ~120 KB native.
2. If more margin needed: custom keccak AIR at degree 5–6 → save ~6–19 KB → ~101–114 KB.
3. WHIR tuning is a minor lever (~2–5 KB) for polish.

WHIR proof size is weakly dependent on column count (logarithmic via padded polynomial
size). Column reduction helps `evals` linearly, not WHIR. The practical floor from
keccak's irreducible state (~1920 cols + sponge) means ~70 KB minimum for `evals`
alone, regardless of AIR design.
