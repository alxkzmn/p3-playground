# HyperPlonk Keccak Proof Size Analysis

Source of truth for HyperPlonk proof size: anatomy, drivers, measurements, and optimization planning.

Conventions: **(M)** = measured from profiler. **(E)** = model estimate. Measured wins on conflict.

---

## 1. Proof anatomy

HyperPlonk is a multi-AIR IOP using LogUp (fractional-sum) for interactions,
with WHIR as the polynomial commitment scheme.

```rust
struct Proof<C> {
    log_bs: Vec<usize>,          // log₂(height) per AIR — 8 bytes each
    commitment: Com<C>,          // single Merkle root — 32 bytes (constant)
    piop: PiopProof<Challenge>,  // ← ~82% of proof (PIOP transcript)
    pcs: Vec<WhirProof>,         // ← ~17% of proof (WHIR PCS opening)
}
```

The proof has **four top-level fields**, but size is concentrated in `piop` and `pcs`.

### 1.1 `piop` — the PIOP transcript (~82% of proof)

```rust
struct PiopProof<Challenge> {
    fractional_sum: FractionalSumProof<Challenge>,  // LogUp tree
    air: AirProof<Challenge>,                       // sumcheck + evals
}
```

**`air`** contains the column evaluations and sumcheck polynomials:

```rust
struct AirProof<Challenge> {
    univariate_skips: Vec<AirUnivariateSkipProof>,       // tiny
    regular: BatchSumcheckProof<Challenge>,               // ← THE BIG ONE
    univariate_eval_check: BatchSumcheckProof<Challenge>, // tiny
}

struct BatchSumcheckProof<Challenge> {
    compressed_round_polys: Vec<CompressedRoundPoly<Challenge>>,  // ~0.6 KB
    evals: Vec<Vec<Challenge>>,  // ← ~99% of air.regular
}
```

**`fractional_sum`** contains the LogUp binary-tree proof for lookup interactions.
When interactions = 0, this is 16 bytes. With 68 interactions, it becomes 25–40 KB.

### 1.2 `pcs` — WHIR PCS opening (~17% of proof)

A `Vec<WhirProof>` (one per opening point). Each WHIR proof contains:

| Sub-component         | Typical bytes | What it is                                        |
| --------------------- | ------------: | ------------------------------------------------- |
| `initial_commitment`  |            32 | Merkle root                                       |
| `initial_ood_answers` |            40 | Out-of-domain evaluations                         |
| `initial_sumcheck`    |           160 | Initial sumcheck round polys                      |
| **`rounds`**          |    **~23 KB** | **FRI-like folding: Merkle auth paths + answers** |
| `final_poly`          |          ~521 | Final folded polynomial coefficients              |
| `final_pow_witness`   |             4 | Proof-of-work grinding witness                    |
| `final_query_batch`   |       ~4.4 KB | Final Merkle authentication batch                 |
| `final_sumcheck`      |          ~177 | Final sumcheck round polys                        |

### 1.3 Constants and metadata

| Field        |      Size | Notes                           |
| ------------ | --------: | ------------------------------- |
| `log_bs`     | 8 per AIR | log₂(height) per AIR            |
| `commitment` |        32 | Single Merkle root for all AIRs |

**Challenge** = `BinomialExtensionField<KoalaBear, 4>` = 4 × 4 bytes = **16 bytes**.

---

## 2. Size drivers per component

### 2.1 `air.regular.evals` — the dominant term

```
evals_bytes ≈ 2 × Σ(width_i) × sizeof(Challenge)
```

Every column costs **32 bytes** (16 for local-row eval + 16 for next-row eval).
This is linear in total AIR width and is the **single largest proof component**.

| Driver                     | Effect                                      | Lever                                       |
| -------------------------- | ------------------------------------------- | ------------------------------------------- |
| **Total AIR width**        | Linear: `+32 bytes` per column              | Reduce columns (primary lever)              |
| Extension field degree `D` | Linear: `sizeof(EF) = 4D` bytes per element | Binomial4 vs Binomial8 (see §5)             |
| Number of AIRs             | Additive: each AIR contributes its width    | Merge AIRs to eliminate lookup table widths |

### 2.2 `fractional_sum` — the interaction cost

| Driver                | Effect                              | Lever                           |
| --------------------- | ----------------------------------- | ------------------------------- |
| **Interaction count** | ~576 bytes per interaction (approx) | Eliminate interactions entirely |
| Trace height          | Grows with more blocks (log factor) | Determined by input size        |

Empirically:

| Interaction count | Mode                            | Measured size |
| ----------------: | ------------------------------- | ------------: |
| 272 (V1 byte XOR) | abandoned                       |   ~157 KB (E) |
|   68 (V2 u16 XOR) | ByteSpongeWithXorLookup         |  25–40 KB (M) |
|                 0 | SingleBlockNoLookup / algebraic |      16 B (M) |

Eliminating interactions is the **highest-ROI single lever** when present.

### 2.3 `air.regular.round_polys` — sumcheck overhead

```
round_poly_bytes ≈ log₂(max_height) × (constraint_degree + 1) × 16
```

| Constraint degree | Bytes (height=256) | Impact           |
| ----------------: | -----------------: | ---------------- |
|                 3 |                576 | Baseline         |
|                 6 |              1,008 | +432 B (+0.4 KB) |
|                 9 |              1,440 | +864 B (+0.8 KB) |

**Negligible** — even at degree 9, under 1.5 KB. Higher degree can save columns (see §4).

### 2.4 WHIR PCS drivers

| Driver              | Effect                                     | Lever                                     |
| ------------------- | ------------------------------------------ | ----------------------------------------- |
| **`num_variables`** | Log in polynomial size → Merkle tree depth | Width thresholds (via power-of-2 padding) |
| Query count         | Linear in Merkle path costs                | Security assumption + `log_inv_rate`      |
| Folding factor      | Controls number of FRI rounds              | Currently Constant(4)                     |

All columns from all AIRs are concatenated and padded to power-of-2 width,
then committed as one multilinear polynomial:

```
polynomial_size = Σ (width_i.next_power_of_two() × height_i)
num_variables = ceil(log₂(polynomial_size))
```

Width affects WHIR **logarithmically** (only through `num_variables`):

| Width range | Padded | PCS variables (h=256) |  WHIR cost |
| ----------- | -----: | --------------------: | ---------: |
| 2049–4096   |   4096 |                    20 | ~28 KB (M) |
| 1025–2048   |   2048 |                    19 | ~25 KB (E) |
| 513–1024    |   1024 |                    18 | ~22 KB (E) |

### 2.5 Security assumption impact on WHIR queries

| Assumption    | δ (proximity) at lir=1 | Queries for 84-bit protocol security |
| ------------- | ---------------------- | ------------------------------------ |
| CapacityBound | 0.475                  | 91                                   |
| JohnsonBound  | 0.257                  | 196                                  |

JohnsonBound requires ~2× more queries, roughly doubling Merkle path costs in WHIR.

---

## 3. Measured baselines

Profile binary: `cargo run --release -p hyperplonk --bin keccak_profile`

Security config:

- `security_bits=100`, `soundness=JohnsonBound` (profiler default), `pow_bits=0`
- `folding_factor=Constant(4)`, `starting_log_inv_rate=6`
- `EF=Binomial4` (124-bit, 16 bytes)

**Note**: The profiler's default config (`JohnsonBound + Binomial4 + lir=6`) causes
an assertion failure (see §5.1). Measurements below were taken under `CapacityBound`
configurations or `SingleBlockNoLookup` mode.

### 3.1 input_size=128, ByteSpongeWithXorLookup (M)

| Component                   |       Value |
| --------------------------- | ----------: |
| `native_proof_size_bytes`   | **141,295** |
| `piop`                      |     119,536 |
| `fractional_sum`            |      24,720 |
| AIR[0] width / interactions |   2909 / 68 |
| AIR[1] width / interactions |      34 / 1 |

### 3.2 input_size=128, SingleBlockNoLookup (M)

| Component                   |        Value |
| --------------------------- | -----------: |
| `native_proof_size_bytes`   | **~113,759** |
| `piop`                      |      ~93,704 |
| `fractional_sum`            |           16 |
| AIR[0] width / interactions |     2909 / 0 |

### 3.3 input_size=1024, ByteSpongeWithXorLookup (M)

| Component                            |       Value |
| ------------------------------------ | ----------: |
| `native_proof_size_bytes`            | **164,061** |
| `piop`                               |     135,168 |
| `fractional_sum`                     |      39,936 |
| `air.regular`                        |      95,144 |
| `air.regular.evals` (computed)       |     ~94,176 |
| `air.regular.round_polys` (residual) |        ~968 |
| AIR[0] width / interactions          |   2909 / 68 |
| AIR[1] width / interactions          |      34 / 1 |
| WHIR PCS                             |     ~28,517 |

### 3.4 Formula cross-check

For measurement 3.3 (total width 2909 + 34 = 2943):

```
evals = 2 × 2943 × 16 = 94,176  ← predicted
air.regular =             95,144  ← measured
residual =                   968  ← round_polys + bincode overhead
```

Formula accuracy: **~99%**. Residual ~968 B = ~576 B round polys + ~400 B serialization.

### 3.5 Key observations

1. Removing interactions (3.1→3.2) saves **~27 KB** at input_size=128.
2. `fractional_sum` grows: 24.7 KB @128 → 39.9 KB @1024.
3. `air.regular.evals` dominates once `fractional_sum` is gone (~93 KB @128 no-lookup).
4. `SingleBlockNoLookup` only works for ≤135 bytes (single Keccak block).

---

## 4. Keccak AIR column anatomy

### 4.1 P3 keccak-air: 2633 permutation columns

| Group             | Shape        |     Cols |     % | Role                             | Max degree |
| ----------------- | ------------ | -------: | ----: | -------------------------------- | ---------: |
| `a_prime`         | `[5][5][64]` | **1600** | 60.8% | Post-θ state bits (core witness) |          2 |
| `c`               | `[5][64]`    |      320 | 12.2% | θ column parities                |          3 |
| `c_prime`         | `[5][64]`    |      320 | 12.2% | Rotated parities                 |          3 |
| `a`               | `[5][5][4]`  |      100 |  3.8% | Packed u16 state (θ output)      |          3 |
| `a_prime_prime`   | `[5][5][4]`  |      100 |  3.8% | Packed χ output                  |          3 |
| `a_pp_0_0_bits`   | `[64]`       |       64 |  2.4% | ι bit decomposition              |          2 |
| `a_ppp_0_0_limbs` | `[4]`        |        4 |  0.2% | ι output (lane 0,0)              |          2 |
| `step_flags`      | `[24]`       |       24 |  0.9% | One-hot round selector           |          2 |
| `preimage`        | `[5][5][4]`  |      100 |  3.8% | Permutation input (sponge)       |          2 |
| `export`          | scalar       |        1 |  0.0% | Sponge export flag               |          2 |

### 4.2 ByteSponge wrapper: +276 sponge columns

| Field                  | Cols | Removable?               |
| ---------------------- | ---: | ------------------------ |
| `hash_end`             |    1 | No                       |
| `seen_end`             |    1 | No                       |
| `active`               |    1 | Yes (= `1 − seen_end`)   |
| `is_new_start`         |    1 | Yes (= `is_first_row()`) |
| `block_bytes[136]`     |  136 | No — message witness     |
| `is_padding_byte[136]` |  136 | No — padding enforcement |

**Total current width: 2633 + 276 = 2909.**

### 4.3 Dependency graph and removability

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

### 4.4 Column removal budget by max degree

|  Max degree | What's removed               | Cols saved | Remaining width | Evals saved |
| ----------: | ---------------------------- | ---------: | --------------: | ----------: |
| 3 (default) | nothing                      |          0 |            2909 |        0 KB |
|           4 | `a_ppp_0_0_limbs`            |          4 |            2905 |      0.1 KB |
|           5 | + `a`, `a_prime_prime`       |        204 |            2705 |      6.5 KB |
|           6 | + `a_pp_0_0_bits`, `c_prime` |        588 |            2321 |     18.8 KB |
|          9+ | Aggressive reformulation     |       ~800 |           ~2100 |    ~25.6 KB |

### 4.5 Practical column floor

`a_prime` (1600) + `c` (320) = **1920 columns**.
Plus sponge (274 non-removable) = **~2194 minimum**.
At `2 × 2194 × 16` = **~70 KB** evals floor for any Keccak AIR on this protocol.

### 4.6 Preprocessed / fixed columns

**Not supported.** `Entry::Preprocessed` exists in `SymbolicVariable` but is dead code.
`is_first_row`, `is_last_row`, `is_transition` are computed analytically from the
sumcheck challenge point — **zero proof bytes**.

Moving `step_flags[24]` to preprocessed trace would save 24 × 32 = 768 bytes.
**Poor ROI for <1 KB savings** given the engineering cost.

---

## 5. Security parameter tradeoffs: JohnsonBound vs CapacityBound

### 5.1 The problem

The profiler's default config (`JohnsonBound + Binomial4 + lir=6`) causes:

```
assertion failed: (1 << bits) <= F::ORDER_U64 as usize
```

at `SerializingChallenger32::grind()`.

**Root cause**: JohnsonBound's weaker proximity parameter requires more proof-of-work
grinding. The WHIR protocol compensates by demanding more PoW bits, but
`grind()` caps PoW at 30 bits for KoalaBear (since `2^31 > p ≈ 2^{31}`).

### 5.2 The math

```
folding_pow_bits = max(0, security_level − min(prox_gaps_error, sumcheck_error))
```

JB proximity-gaps error uses `2·num_vars` in the numerator (vs `1·num_vars` for CB).
This halves the available soundness bits per query.

Computed for `num_vars=20` (HyperPlonk's PCS polynomial at height=256, padded width=4096):

| Assumption |    EF bits |    lir=1 | lir=3 |    lir=6 |
| ---------- | ---------: | -------: | ----: | -------: |
| **CB**     | 124 (Bin4) |      6.3 |  12.3 |     21.3 |
| **JB**     | 124 (Bin4) | **42.8** |  49.8 | **60.3** |
| CB         | 248 (Bin8) |      0.0 |   0.0 |      0.0 |
| **JB**     | 248 (Bin8) |  **0.0** |   0.0 |      0.0 |

KoalaBear PoW ceiling = **30 bits**. JB + Binomial4 exceeds this at **all** `log_inv_rate` values.
The profiler's config (`lir=6`) requires 60+ bits of PoW — doubly impossible.

### 5.3 The only parameter-level fix: Binomial8

Switching to `BinomialExtensionField<KoalaBear, 8>` (248-bit EF, 32 bytes per element)
makes `prox_gaps_error > 180` bits, so `folding_pow_bits = 0`.

**Proof size impact of Binomial8 + JohnsonBound:**

| Component           | Bin4+CB (current) | Bin8+JB (projected) | Reason                             |
| ------------------- | ----------------- | ------------------- | ---------------------------------- |
| `air.regular.evals` | ~94 KB            | **~188 KB**         | `sizeof(EF)` doubles: 16→32 bytes  |
| `fractional_sum`    | 25–40 KB          | ~50–80 KB (E)       | All elements double                |
| WHIR PCS            | ~28 KB            | ~45–55 KB (E)       | ~2× queries (JB) + larger sumcheck |
| **Native total**    | **141–164 KB**    | **~280–320 KB (E)** | ~2× overall                        |

Binomial8 roughly doubles proof size. It is the **only way** to use JohnsonBound
(proven security assumption) with a 31-bit base field at 100-bit security.

### 5.4 What does NOT fix JohnsonBound + Binomial4

| Knob                                    | Why it fails                                                 |
| --------------------------------------- | ------------------------------------------------------------ |
| Increase `log_inv_rate`                 | JB folding_pow grows ~3.5 bits per lir step — makes it worse |
| Increase PoW ceiling                    | Required bits already exceed 30; ceiling doesn't matter      |
| Reduce `num_variables`                  | Need `nv ≤ 13` (width ≤ 256); impractical for keccak         |
| Larger folding factor                   | Doesn't affect `prox_gaps_error` (the bottleneck)            |
| `univariate_skips`                      | Changes sumcheck, not polynomial dimension                   |
| Modify challenger for multi-element PoW | Invasive protocol change to Plonky3                          |

### 5.5 Practical recommendation

Stay on **Binomial4 + CapacityBound** for proof-size benchmarks. CB relies on a
conjecture (RS capacity decodability + correlated agreement), but it is widely
used in production and gives 2× smaller proofs than Bin8+JB. Reserve JB for
contexts where provable security is required and proof size is secondary.

---

## 6. Strategy comparison

All for keccak-256, Binomial4, CapacityBound, 100-bit security.

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

### Binomial8 + JohnsonBound (projected)

| Strategy                              |   Width |   Evals | Frac.Sum |   WHIR | **Native total** |
| ------------------------------------- | ------: | ------: | -------: | -----: | ---------------: |
| ByteSponge+XorLookup @ 128 **(E)**    | 2909+34 | ~188 KB |   ~50 KB | ~45 KB |      **~283 KB** |
| No interactions, deg 6 @ 1024 **(E)** |   ~2321 | ~148 KB |        0 | ~50 KB |      **~200 KB** |

---

## 7. Optimization levers (ranked by ROI)

| #     | Lever                                            |                  Savings | Difficulty   | Status                         |
| ----- | ------------------------------------------------ | -----------------------: | ------------ | ------------------------------ |
| **1** | **Kill all interactions** (algebraic absorb XOR) |             **25–40 KB** | Medium       | Proposed; not implemented      |
| **2** | **Remove intermediate columns** (degree 5–6)     |                  6–19 KB | High         | Requires forking keccak-air    |
| **3** | Tune WHIR parameters                             |                   2–5 KB | Low          | Secondary                      |
| —     | Switch to JohnsonBound                           | Negative (doubles proof) | Low          | Only viable with Bin8 (see §5) |
| —     | Smaller extension field                          |                   ~47 KB | Infeasible   | Violates 100-bit security      |
| —     | Different hash function                          |                  ~60+ KB | Out of scope | Not aligned with Keccak goals  |

### Per-column savings law

Removing one witness column saves exactly **32 bytes** of native proof
(`2 × sizeof(EF)` from local + next row evaluations in `air.regular.evals`).

### Degree vs prover cost

| Constraint degree | Round poly bytes (9 rounds) | Prover overhead |
| ----------------: | --------------------------: | --------------- |
|                 3 |                       576 B | Baseline        |
|                 6 |                     1,008 B | ~1.75× sumcheck |
|                 9 |                     1,440 B | ~2.5× sumcheck  |

Round poly overhead is negligible. Degree 5–6 is the sweet spot for column savings.

---

## 8. Roadmap and acceptance gates

### Phase A — done

- `SingleBlockNoLookup` mode for `input_size ≤ 135`.
- Confirmed `interaction_count = 0` eliminates fractional-sum overhead.
- Profiled all modes at multiple input sizes.

### Phase B — next (highest ROI)

- Add algebraic absorb XOR mode (single AIR, width 2909, zero interactions).
- Cross-block absorb XOR enforced via constraints on existing columns.

### Phase C — measure and gate

- Profile at `input_size = 128, 1024, 2048`.
- Gate on acceptance criteria below.

### Phase D — optional: custom narrow AIR

- Fork keccak-air, raise degree to 5–6, remove `a`, `a_prime_prime`, `c_prime`, `a_pp_0_0_bits`.
- Expected additional savings: 6–19 KB.

### Acceptance gates

| #   | Gate                             | Threshold                              |
| --- | -------------------------------- | -------------------------------------- |
| 1   | `interaction_count` for all AIRs | `== 0`                                 |
| 2   | `fractional_sum` serialized size | `≤ 64 bytes`                           |
| 3   | `native_proof_size_bytes`        | `< 131,072` (128 KB) for 1–2 KB inputs |
| 4   | Correctness                      | All keccak + blob codec tests pass     |
| 5   | Prove-time regression            | `< 2×` vs current ByteSponge mode      |

If gate 3 fails after Phase B, proceed to Phase D (custom AIR).

---

## 9. Reference formulas

### 9.1 `air.regular.evals` prediction

```
evals_bytes ≈ 2 × (Σ width_i) × sizeof(Challenge)
```

Where `sizeof(Challenge)` = 16 (Bin4) or 32 (Bin8).

Cross-check: at width 2943, predicted = 94,176 B, measured = 95,144 B. **~99% accurate.**

### 9.2 Per-column cost (general)

```
cost_per_column = 2 × sizeof(Challenge) = { 32 bytes (Bin4), 64 bytes (Bin8) }
```

### 9.3 WHIR polynomial size

```
pcs_poly_size = Σ (width_i.next_power_of_two() × height_i)
num_variables = ceil(log₂(pcs_poly_size))
```

A jump in `num_variables` causes a step increase in WHIR proof size.

### 9.4 Fractional-sum diagnostic

If `fractional_sum` serialized size > 100 bytes and you expected zero interactions:
**bug** — check `push_send` / `push_receive` calls and `enable_lookup_interactions` flag.
