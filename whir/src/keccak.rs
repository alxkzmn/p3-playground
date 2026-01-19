use alloc::vec;
use alloc::vec::Vec;

use p3_field::{PackedValue, PrimeField32};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

pub const KECCAK_DIGEST_ELEMS: usize = 4;

pub fn digest_u64_to_bytes32(digest: &[u64; KECCAK_DIGEST_ELEMS]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in digest.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn digest_bytes32_to_u64(bytes: &[u8; 32]) -> [u64; KECCAK_DIGEST_ELEMS] {
    let mut out = [0u64; KECCAK_DIGEST_ELEMS];
    for i in 0..KECCAK_DIGEST_ELEMS {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_be_bytes(word);
    }
    out
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakU32BeLeafHasher;

impl<P> CryptographicHasher<P, [u64; KECCAK_DIGEST_ELEMS]> for KeccakU32BeLeafHasher
where
    P: PackedValue,
    P::Value: PrimeField32,
{
    fn hash_iter<I>(&self, input: I) -> [u64; KECCAK_DIGEST_ELEMS]
    where
        I: IntoIterator<Item = P>,
    {
        let mut iter = input.into_iter();
        let mut preimage = if let Some(first) = iter.next() {
            let elems_per_packed = first.as_slice().len();
            let (lower, _) = iter.size_hint();
            let mut buf = Vec::with_capacity(1 + (lower + 1) * elems_per_packed * 4);
            buf.push(0x00);
            for &x in first.as_slice() {
                buf.extend_from_slice(&x.as_canonical_u32().to_be_bytes());
            }
            buf
        } else {
            let buf = vec![0x00];
            buf
        };

        for packed in iter {
            for &x in packed.as_slice() {
                preimage.extend_from_slice(&x.as_canonical_u32().to_be_bytes());
            }
        }
        let bytes: [u8; 32] = Keccak256Hash.hash_iter(preimage);
        digest_bytes32_to_u64(&bytes)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakNodeCompress;

impl PseudoCompressionFunction<[u64; KECCAK_DIGEST_ELEMS], 2> for KeccakNodeCompress {
    fn compress(&self, input: [[u64; KECCAK_DIGEST_ELEMS]; 2]) -> [u64; KECCAK_DIGEST_ELEMS] {
        let prefix = [0x01u8];
        let left = digest_u64_to_bytes32(&input[0]);
        let right = digest_u64_to_bytes32(&input[1]);
        let bytes: [u8; 32] = Keccak256Hash.hash_iter_slices([&prefix[..], &left[..], &right[..]]);
        digest_bytes32_to_u64(&bytes)
    }
}
