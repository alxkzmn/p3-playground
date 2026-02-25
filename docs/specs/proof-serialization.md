# HyperPlonk EVM Proof Serialization v2

This document defines the canonical wire format emitted by `evm_vectors` for on-chain verification.

## Goals

- Keep calldata minimal for `verify(bytes)` calls.
- Preserve deterministic encoding and strict decoding.
- Keep decode compatibility for legacy v1 vectors.

## Outputs

The example supports two output modes:

1. `json` (default): metadata + proof blob + wallet-ready calldata.
2. `calldata`: wallet-ready transaction data for `verify(bytes)`.

## Fixed verifier entrypoint

- Function signature: `verify(bytes)`
- Calldata format: `selector || abi.encode(bytes proof_blob)`
- `selector` is the first 4 bytes of `keccak256("verify(bytes)")`.

## JSON schema (`p3-hyperplonk-evm-proof-v2`)

```json
{
  "schema": "p3-hyperplonk-evm-proof-v2",
  "verify_function": "verify(bytes)",
  "selector": "0x....",
  "keccak_mode": "prefixed|no_prefix",
  "proof_bytes": "0x....",
  "proof_bytes_len": 0,
  "calldata": "0x....",
  "calldata_len": 0,
  "hash_counts_prover": { "leaf_hash_calls": 0, "node_hash_calls": 0 },
  "hash_counts_verifier": { "leaf_hash_calls": 0, "node_hash_calls": 0 },
  "hash_counts_total": { "leaf_hash_calls": 0, "node_hash_calls": 0 }
}
```

## Binary proof blob

### Envelope

- `magic[4] = "HPK1"`
- `version:u8`
  - `2` => v2 compact query-batch encoding (default for new vectors)
  - `1` => legacy v1 encoding (still decodable)

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
   - `query_batch`
   - `sumcheck`
5. `final_poly` (option tagged)
6. `final_pow_witness`
7. `final_query_batch`
8. `final_sumcheck` (option tagged)

## Query-batch encoding

### v1 (legacy)

- `query_kind:u8` (`0=base`, `1=extension`)
- `query_count:varuint`
- `row_width:varuint`
- `values_flat` (`query_count * row_width`)
- `decommit_count:varuint`
- `decommitments[decommit_count]:digest`

### v2 (compact, default)

- `values_flat` only
- `decommitments` only
- The following are not serialized in v2:
  - `query_kind`
  - `query_count`
  - `row_width`
  - `decommit_count`

In v2, query shape is derived from transcript/protocol round context (same design intent as old `whir-verifier` / `sol-whir` flow).

## Primitive encodings

- `varuint`: canonical unsigned LEB128 (minimal representation only).
- `base_field` (`KoalaBear`): 4-byte big-endian canonical limb.
- `extension_field` (`BinomialExtensionField<_,4>`): 4 base limbs in order, each 4-byte big-endian.
- `digest`: bytes32 canonical map of `[u64;4]`.
- `option`: 1-byte tag (`0=None`, `1=Some`) plus payload for `Some`.

## Strict decoding rules

Decoders MUST reject:

- unsupported `version`,
- trailing bytes after top-level proof payload,
- non-canonical varuint encoding,
- unknown enum/option tags,
- malformed ABI calldata (`verify(bytes)` selector mismatch, bad offset/length/padding),
- malformed `final_poly` lengths (must be power-of-two when present),
- v2 payloads where decoded element counts do not match derived query shape.

## Compatibility guidance

- New vectors should be emitted as v2.
- v1 decode remains supported for legacy artifacts and regression tests.

## TODO (deferred optimization)

- Replace per-query `open_batch` extraction in multiproof assembly with an `open_multi` / layer-access path.
- Expected effect: lower prover CPU and RAM overhead in multiproof construction without changing proof semantics.
