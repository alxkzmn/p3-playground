# HyperPlonk EVM Proof Serialization v1

This document defines the canonical wire format emitted by `evm_vectors` for on-chain verification.

## Goals

- Include all verifier-required proof material (HyperPlonk + WHIR + public inputs).
- Keep v1 minimal and deterministic (no debug-only redundancy).
- Preserve forward compatibility for future size optimizations.

## Outputs

The example supports two output modes:

1. `json` (default): canonical metadata + proof blob + wallet-ready calldata.
2. `calldata`: wallet-ready transaction data for `verify(bytes)`.

## Fixed verifier entrypoint

- Function signature: `verify(bytes)`
- Calldata format: `selector || abi.encode(bytes proof_blob_v1)`
- `selector` is the first 4 bytes of `keccak256("verify(bytes)")`.

## JSON schema (`p3-hyperplonk-evm-proof-v1`)

```json
{
  "schema": "p3-hyperplonk-evm-proof-v1",
  "verify_function": "verify(bytes)",
  "selector": "0x....",
  "proof_bytes": "0x....",
  "proof_bytes_len": 0,
  "calldata": "0x....",
  "calldata_len": 0
}
```

## Binary proof blob (`proof_blob_v1`)

### Envelope

- `magic[4] = "HPK1"`
- `version:u8 = 1`

### Public input section

- `air_count:varuint`
- For each AIR:
  - `public_values_len:varuint`
  - `public_value[i]:base_field`

### HyperPlonk proof section

Encodes all verifier-required fields in this order:

1. `log_bs`
2. `commitment`
3. `piop.fractional_sum`
4. `piop.air`
5. `pcs` (vector of WHIR proofs)

### WHIR proof section (per PCS proof)

For each WHIR proof, encode:

1. `initial_commitment`
2. `initial_ood_answers`
3. `initial_sumcheck`
4. `rounds`:
   - `commitment`
   - `ood_answers`
   - `pow_witness`
   - `queries`
   - `sumcheck`
5. `final_poly` (option tagged)
6. `final_pow_witness`
7. `final_queries`
8. `final_sumcheck` (option tagged)

## Primitive encodings

- `varuint`: canonical unsigned LEB128 (ULEB128, minimal form only).
- `base_field` (`KoalaBear`): 4-byte big-endian canonical limb (`as_canonical_u32().to_be_bytes()`).
- `extension_field` (`BinomialExtensionField<_,4>`): 4 base limbs in order, each 4-byte big-endian.
- `digest`: bytes32 canonical map of `[u64;4]`:
  - `bytes32 = u64_be[0] || u64_be[1] || u64_be[2] || u64_be[3]`
- `option`: 1-byte tag (`0 = None`, `1 = Some`), followed by payload for `Some`.
- `query kind`: 1-byte tag (`0 = base`, `1 = extension`).

## Determinism and strict decoding

Decoders MUST reject:

- trailing bytes after parsing the top-level proof blob,
- non-canonical varuint representations,
- unknown enum/option tags,
- malformed ABI calldata (`verify(bytes)` selector mismatch, bad offset/length/padding),
- malformed `final_poly` lengths (must be power-of-two when present).

## Compatibility guidance

- v1 is intentionally minimal for correctness and benchmarking.
- Future compression/packing changes should use a new version while preserving `verify(bytes)` call shape.
