use p3_air::{Air, AirBuilder, BaseAir, BaseAirWithPublicValues};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::BasedVectorSpace;
use p3_hyperplonk::{HyperPlonkConfig, ProverInput, keygen, prove};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_poseidon2_air::{RoundConstants, generate_trace_rows, num_cols};
use p3_whir::{
    FoldingFactor, InitialPhaseConfig, KeccakNodeCompress, KeccakU32BeLeafHasher,
    ProtocolParameters, SecurityAssumption, WhirPcsKeccak, digest_u64_to_bytes32,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use whir_p3::whir::proof::WhirProof;

type Val = KoalaBear;
type Challenge = BinomialExtensionField<Val, 4>;
type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;

const DIGEST_BYTES: usize = 32;

type FieldHash = KeccakU32BeLeafHasher;
type Compress = KeccakNodeCompress;
type Dft<Val> = Radix2DitParallel<Val>;
type Pcs<Val, Dft> = WhirPcsKeccak<Val, Dft, FieldHash, Compress>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>;

const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = 3;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 20;

pub struct Poseidon2Air(
    p3_poseidon2_air::Poseidon2Air<
        Val,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
);

impl BaseAir<Val> for Poseidon2Air {
    fn width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }
}

impl BaseAirWithPublicValues<Val> for Poseidon2Air {}

impl<AB: AirBuilder<F = Val>> Air<AB> for Poseidon2Air {
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
    }
}

fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex32(x: &[u8; 32]) -> String {
    hex(x)
}

fn encode_val_u32_be(x: Val) -> [u8; 4] {
    x.as_canonical_u32().to_be_bytes()
}

fn encode_challenge_bytes(ch: Challenge) -> Vec<u8> {
    // Extension element = 4 base limbs (KoalaBear), each encoded as u32 BE.
    let mut out = Vec::with_capacity(16);
    for limb in Challenge::flatten_to_base(vec![ch]) {
        out.extend_from_slice(&encode_val_u32_be(limb));
    }
    out
}

fn leaf_hash_from_bytes(leaf_payload: &[u8]) -> [u8; 32] {
    let prefix = [0x00u8];
    Keccak256Hash.hash_iter_slices([&prefix[..], leaf_payload])
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0);

    let config = {
        let dft = Dft::default();
        let security_level = 100;
        let pow_bits = 20;
        let whir_params = ProtocolParameters {
            initial_phase_config: InitialPhaseConfig::WithStatementClassic,
            security_level,
            pow_bits,
            folding_factor: FoldingFactor::Constant(4),
            merkle_hash: FieldHash::default(),
            merkle_compress: Compress::default(),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 3,
        };
        HyperPlonkConfig::<_, Challenge, _>::new(
            Pcs::new(dft, whir_params),
            Challenger::from_hasher(Vec::new(), Keccak256Hash),
        )
    };

    let round_constants = RoundConstants::from_rng(&mut rng);
    let make_air = || Poseidon2Air(p3_poseidon2_air::Poseidon2Air::new(round_constants.clone()));
    let air = make_air();
    let (_vk, pk) = keygen([&air]);

    let log_b = 15;
    let trace = generate_trace_rows::<
        _,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(
        (0..1 << log_b).map(|_| rng.random()).collect(),
        &round_constants,
        0,
    );

    let prover_inputs = vec![ProverInput::new(make_air(), Vec::new(), trace)];
    let proof = prove(&config, &pk, prover_inputs);

    // PCS proof is a `Vec<WhirProof<Val, Challenge, u64, 4>>`.
    let pcs_proofs: &Vec<WhirProof<Val, Challenge, u64, 4>> = &proof.pcs;

    println!("{{");
    // HyperPlonk commitment (PCS commitment) is bytes32 in Keccak mode.
    println!(
        "  \"commitment_bytes32\": \"0x{}\",",
        hex(&digest_u64_to_bytes32(proof.commitment.as_ref()))
    );
    println!("  \"pcs\": [");
    for (pi, pcs) in pcs_proofs.iter().enumerate() {
        println!("    {{");
        println!(
            "      \"initial_root\": \"0x{}\",",
            hex32(&digest_u64_to_bytes32(&pcs.initial_commitment))
        );

        // Initial openings live in round proofs / final_queries; we dump them all.
        println!("      \"rounds\": [");
        for (ri, round) in pcs.rounds.iter().enumerate() {
            println!("        {{");
            println!("          \"round_index\": {},", ri);
            println!(
                "          \"root\": \"0x{}\",",
                hex32(&digest_u64_to_bytes32(&round.commitment))
            );
            println!("          \"queries\": [");
            for (qi, q) in round.queries.iter().enumerate() {
                let (kind, payload, siblings) = if let Some(vals) = q.base_values() {
                    let mut payload = Vec::<u8>::with_capacity(vals.len() * 4);
                    for &v in vals {
                        payload.extend_from_slice(&encode_val_u32_be(v));
                    }
                    ("base", payload, q.merkle_proof())
                } else {
                    let vals = q.extension_values().expect("extension opening");
                    let mut payload = Vec::<u8>::with_capacity(vals.len() * 16);
                    for &v in vals {
                        payload.extend_from_slice(&encode_challenge_bytes(v));
                    }
                    ("extension", payload, q.merkle_proof())
                };

                let leaf = leaf_hash_from_bytes(&payload);
                println!("            {{");
                println!("              \"query_index\": {},", qi);
                println!("              \"kind\": \"{}\",", kind);
                println!("              \"leaf_payload\": \"0x{}\",", hex(&payload));
                println!("              \"leaf_hash\": \"0x{}\",", hex32(&leaf));
                println!("              \"siblings\": [");
                for (si, sib) in siblings.iter().enumerate() {
                    let comma = if si + 1 == siblings.len() { "" } else { "," };
                    let sib_bytes = digest_u64_to_bytes32(sib);
                    println!("                \"0x{}\"{}", hex32(&sib_bytes), comma);
                }
                println!("              ]");
                let comma = if qi + 1 == round.queries.len() {
                    ""
                } else {
                    ","
                };
                println!("            }}{comma}");
            }
            println!("          ]");
            let comma = if ri + 1 == pcs.rounds.len() { "" } else { "," };
            println!("        }}{comma}");
        }
        println!("      ],");

        println!("      \"final_queries\": [");
        for (qi, q) in pcs.final_queries.iter().enumerate() {
            let (kind, payload, siblings) = if let Some(vals) = q.base_values() {
                let mut payload = Vec::<u8>::with_capacity(vals.len() * 4);
                for &v in vals {
                    payload.extend_from_slice(&encode_val_u32_be(v));
                }
                ("base", payload, q.merkle_proof())
            } else {
                let vals = q.extension_values().expect("extension opening");
                let mut payload = Vec::<u8>::with_capacity(vals.len() * 16);
                for &v in vals {
                    payload.extend_from_slice(&encode_challenge_bytes(v));
                }
                ("extension", payload, q.merkle_proof())
            };

            let leaf = leaf_hash_from_bytes(&payload);
            println!("        {{");
            println!("          \"query_index\": {},", qi);
            println!("          \"kind\": \"{}\",", kind);
            println!("          \"leaf_payload\": \"0x{}\",", hex(&payload));
            println!("          \"leaf_hash\": \"0x{}\",", hex32(&leaf));
            println!("          \"siblings\": [");
            for (si, sib) in siblings.iter().enumerate() {
                let comma = if si + 1 == siblings.len() { "" } else { "," };
                println!("            \"0x{}\"{}", hex32(sib), comma);
            }
            println!("          ]");
            let comma = if qi + 1 == pcs.final_queries.len() {
                ""
            } else {
                ","
            };
            println!("        }}{comma}");
        }
        println!("      ]");

        let comma = if pi + 1 == pcs_proofs.len() { "" } else { "," };
        println!("    }}{comma}");
    }
    println!("  ]");
    println!("}}");
}
