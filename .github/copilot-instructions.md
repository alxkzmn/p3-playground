# Copilot instructions for p3-playground

## Big picture (workspace layout)
- This is a Rust workspace of experimental Plonky3-based crates (all `#![no_std]` + `extern crate alloc`). Keep additions `no_std`-friendly unless a crate explicitly enables `std`.
- Major crates:
  - `air-ext`: symbolic AIR builder + constraint checking helpers.
  - `fri-ext`: FRI LDT implementation.
  - `uni-stark-ext`: minimal univariate STARK framework.
  - `hyperplonk`: HyperPlonk + sumcheck; main `prove()`/`verify()` live in `hyperplonk/src/prover.rs` and `hyperplonk/src/verifier.rs`.
  - `ml-pcs`: multilinear PCS trait/utilities used by HyperPlonk and WHIR.
  - `whir`: adapter that wraps `whir-p3` to implement the multilinear PCS trait.
  - `poseidon2-util`: Poseidon2 constants + AIR helpers.

## Protocol flow conventions (important for correctness)
- Fiat–Shamir observation order must match prover/verifier exactly.
  - HyperPlonk observes `log_b` values, then commitment, then public values (see `hyperplonk/src/prover.rs` and `hyperplonk/src/verifier.rs`).
  - WHIR PCS fixes transcript via `DomainSeparator` before committing/reading proof (see `whir/src/pcs.rs`).
- WHIR uses two Merkle flavors: field-hash and Keccak bytes32. The Keccak flavor maps `[u64;4]` ↔ bytes32 big-endian and uses explicit domain separation prefixes 0x00 (leaf) / 0x01 (node). Keep any hashing/serialization changes consistent with `whir/src/keccak.rs` and `docs/specs/proof-serialization.md`.
- In `whir/src/pcs.rs`, adding any explicit linear constraints forces `InitialPhase::WithStatement` (see the `has_linear_constraints()` branch). Preserve that behavior when extending constraints.

## Project-specific patterns
- Parallelism is gated behind the `parallel` feature and uses `p3-maybe-rayon` (see `whir/Cargo.toml` and `hyperplonk/Cargo.toml`). Avoid unconditional rayon usage.
- Constraint checking is opt-in via the `check-constraints` feature (air-ext, hyperplonk, uni-stark-ext). Keep debug-only checks behind that feature.
- Instrumentation uses `tracing` spans (e.g., `info_span!`, `instrument`) in hot paths; follow existing span naming if you add steps.

## Common workflows
- Workspace build/test: `cargo test --workspace`
- Per-crate tests: `cargo test -p p3-hyperplonk`, `cargo test -p p3-uni-stark-ext`, `cargo test -p p3-whir`
- Benches (HyperPlonk): `cargo bench -p p3-hyperplonk --features bench`
- Constraint checking: `cargo test -p p3-hyperplonk --features check-constraints`

## Integration points
- External dependency `whir-p3` is wrapped in `whir` to satisfy `p3-ml-pcs::MlPcs`.
- Plonky3 crates are pinned via workspace patches (see root `Cargo.toml`), so avoid bumping versions without updating the patch section.
