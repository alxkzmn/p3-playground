# HyperPlonk EVM Proof Serialization (v1/v2/v3)

This document defines HyperPlonk EVM proof blob formats used by `evm_vectors`.

## Version semantics

- `v1`: explicit legacy format.
- `v2`: compact format with full `bytes32` Merkle digests.
- `v3`: compact format with masked/truncated Merkle digests.

`evm_vectors` now emits `v3` by default.

## Goals

- Minimize calldata bytes for `verify(bytes)`.
- Keep deterministic encoding and strict decoding.
- Preserve explicit legacy decode paths for test fixtures.

## Fixed verifier entrypoint

- Function signature: `verify(bytes)`.
- Calldata format: `selector || abi.encode(bytes proof_blob)`.
- `selector = keccak256("verify(bytes)")[0..4]`.

## JSON payload

Schema values:

- `v1`: `p3-hyperplonk-evm-proof-v1`
- `v2`: `p3-hyperplonk-evm-proof-v2`
- `v3`: `p3-hyperplonk-evm-proof-v3`

Rendered JSON includes:

- `proof_blob_version`
- `keccak_mode`
- `masked_digest_bytes`
- `masked_digest_bits`
- `merkle_security_bits`
- `merkle_security_bits_override`
- `merkle_override_weaker_than_security`
- `total_merkle_digest_count`
- `proof_bytes` and `proof_bytes_len`
- `calldata` and `calldata_len`
- `calldata_gas_estimate`
- `hash_counts_prover`, `hash_counts_verifier`, `hash_counts_total`

## Binary proof blob

### Envelope

- `magic[4] = "HPK1"`
- `version:u8` (`1|2|3`)

### Public input section

- `air_count:varuint`
- For each AIR:
  - `public_values_len:varuint`
  - `public_value[i]:base_field`

### HyperPlonk proof section

In order:

1. `log_bs`
2. `commitment`
3. `piop.fractional_sum`
4. `piop.air`
5. `pcs` (vector of WHIR proofs)

### WHIR proof section (per PCS proof)

In order:

1. `initial_commitment`
2. `initial_ood_answers`
3. `initial_sumcheck`
4. `rounds[]`:

- `commitment`
- `ood_answers`
- `pow_witness`
- `query_batch`
- `sumcheck`

5. `final_poly` (option-tagged)
6. `final_pow_witness`
7. `final_query_batch`
8. `final_sumcheck` (option-tagged)

## Query-batch encoding

### v1 (legacy)

- `query_kind:u8` (`0=base`, `1=extension`)
- `query_count:varuint`
- `row_width:varuint`
- `values_flat`
- `decommit_count:varuint`
- `decommitments[decommit_count]`

### v2 and v3 (compact)

Only payload arrays are encoded:

- `values_flat`
- `decommitments`

Not encoded in compact modes:

- `query_kind`
- `query_count`
- `row_width`
- `decommit_count`

Decoder derives query shape from transcript/protocol round context.

## Digest encoding by version

- `v1`, `v2`: Merkle digests serialized as full 32 bytes.
- `v3`: Merkle digests serialized as `effective_digest_bytes` and zero-padded back to 32 bytes during decode.

`effective_digest_bytes` is security-coupled (`ceil(2 * security_bits / 8)`, clamped to `[1,32]`).

## Manual Merkle override

`evm_vectors` supports `--merkle-security-bits <usize>`.

Resolved Merkle masking security is:

- `merkle_security_bits = merkle_security_bits_override.unwrap_or(security_bits)`

Digest width is then:

- `effective_digest_bytes = ceil(2 * merkle_security_bits / 8)` (clamped to `[1,32]`)

This override is a research knob and may reduce Merkle binding security below global protocol security. No wire-format change is introduced by this override.

## Primitive encodings

- `varuint`: canonical unsigned LEB128 (minimal only).
- `base_field` (`KoalaBear`): 4-byte big-endian limb.
- `extension_field` (`BinomialExtensionField<_,4>`): 4 base limbs.
- `option`: `0=None`, `1=Some` + payload.

## Strict decode rules

Decoders reject:

- unsupported `version`
- missing required context for compact decode
- non-canonical varuint
- malformed enum/option tags
- malformed ABI wrapper for `verify(bytes)`
- malformed `final_poly` lengths (must be power-of-two if present)
- compact payload lengths that do not match derived shape
- malformed/truncated digest payloads
- trailing bytes

## Solidity follow-up for v3

`v3` requires on-chain parser/verifier support for truncated digest bytes, with zero-padding to `bytes32` before hash checks. This cycle does not modify `/Users/alexkuzmin/development/zkid-benchmarks/sol-whir`.

## Deferred TODO

- Avoid per-query `open_batch` extraction during multiproof assembly (move toward multi-open/layer access).
- Target effect: reduce prover CPU/RAM overhead without proof semantic changes.
