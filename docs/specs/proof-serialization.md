# WHIR Keccak proof serialization (bytes32 canonical form)

This document defines the canonical, on-chain friendly encoding for Keccak-based WHIR proofs.
It targets minimal gas usage and deterministic transcript reconstruction.

## Digest representation

- **Internal (off-chain) digest type:** `[u64; 4]` (SIMD-friendly).
- **Wire / on-chain digest type:** `bytes32`.
- **Canonical mapping:** big-endian u64 chunks.

```
bytes32 = u64_be[0] || u64_be[1] || u64_be[2] || u64_be[3]
```

## Merkle hashing

All Merkle hashing uses Keccak256 with explicit domain separation prefixes.

- **Leaf hash**: `Keccak256(0x00 || leaf_payload)`
- **Node hash**: `Keccak256(0x01 || left || right)`

Where:

- `left`/`right` are 32-byte digests in the canonical bytes32 form above.
- `leaf_payload` is the byte encoding of the opened values for the query (see below).

### Leaf payload encoding

For each base field element $f$:

- encode as big-endian 32-bit limb: `f.as_canonical_u32().to_be_bytes()`.

For each extension field element $e$ with $k$ base limbs:

- serialize the limbs in order, each as big-endian 32-bit, then concatenate.

## Fiat–Shamir transcript observation order

All prover and verifier implementations must observe values in the exact same order.
The ordering is:

1. Domain separator bytes (the full WHIR transcript pattern).
2. Initial commitment root (bytes32).
3. Initial OOD answers (field elements, canonical field encoding).
4. Per-round commitments and openings as specified by the protocol.

The concrete transcript layout is determined by WHIR’s domain separator pattern and must be
applied identically off-chain and on-chain.

## Compatibility notes

- The on-chain verifier should only consume bytes32 digests.
- Off-chain uses `[u64; 4]` and converts to/from bytes32 **only** at the I/O boundary.
- Endianness is fixed to big-endian at all boundaries to avoid ambiguity.
