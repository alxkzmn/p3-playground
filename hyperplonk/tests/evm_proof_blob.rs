use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_hyperplonk::{HyperPlonkConfig, ProverInput, VerifierInput, keygen, prove, verify};
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_whir::{
    FoldingFactor, KeccakNodeCompress, KeccakU32BeLeafHasher, ProtocolParameters,
    SecurityAssumption, WhirPcs,
};

#[path = "../src/evm_codec.rs"]
mod evm_codec;

use evm_codec::{
    Challenge, DecodedProofBlob, HyperPlonkProof, Val, decode_proof_blob_v1,
    decode_verify_bytes_calldata, encode_calldata_verify_bytes, encode_proof_blob_v1,
    encode_proof_blob_v1_with_offsets, render_json_payload, verify_bytes_selector,
};

type FieldHash = KeccakU32BeLeafHasher;
type Compress = KeccakNodeCompress;
type Dft = Radix2DitParallel<Val>;
type Pcs = WhirPcs<Val, Dft, FieldHash, Compress, 4>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>;

#[derive(Clone, Copy)]
struct CounterAir;

impl BaseAir<Val> for CounterAir {
    fn width(&self) -> usize {
        1
    }
}

impl BaseAirWithPublicValues<Val> for CounterAir {
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilderWithPublicValues<F = Val>> Air<AB> for CounterAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        let public_value = builder.public_values()[0].clone();

        builder
            .when_transition()
            .assert_eq(local[0].clone() + AB::Expr::ONE, next[0].clone());
        builder
            .when_last_row()
            .assert_eq(local[0].clone(), public_value);
    }
}

struct Fixture {
    config: HyperPlonkConfig<Pcs, Challenge, Challenger>,
    vk: p3_hyperplonk::VerifyingKey,
    proof: HyperPlonkProof,
    public_inputs: Vec<Vec<Val>>,
    air: CounterAir,
}

fn make_counter_trace(log_b: usize) -> RowMajorMatrix<Val> {
    let rows = 1 << log_b;
    RowMajorMatrix::new_col((0..rows).map(Val::from_usize).collect())
}

fn build_fixture() -> Fixture {
    let config = {
        let whir_params = ProtocolParameters {
            security_level: 60,
            pow_bits: 0,
            folding_factor: FoldingFactor::Constant(4),
            merkle_hash: FieldHash::default(),
            merkle_compress: Compress::default(),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 3,
        };
        HyperPlonkConfig::<_, Challenge, _>::new(
            Pcs::new(Dft::default(), whir_params),
            Challenger::from_hasher(Vec::new(), Keccak256Hash),
        )
    };

    let air = CounterAir;
    let (vk, pk) = keygen([&air]);

    let log_b = 8;
    let trace = make_counter_trace(log_b);
    let public_values = vec![Val::from_usize((1 << log_b) - 1)];

    let proof = prove(
        &config,
        &pk,
        vec![ProverInput::new(air, public_values.clone(), trace)],
    );

    let verifier_inputs = vec![VerifierInput::new(air, public_values.clone())];
    verify(&config, &vk, verifier_inputs, &proof).unwrap();

    Fixture {
        config,
        vk,
        proof,
        public_inputs: vec![public_values],
        air,
    }
}

fn verifier_inputs_from_publics(
    air: CounterAir,
    public_inputs: &[Vec<Val>],
) -> Vec<VerifierInput<Val, CounterAir>> {
    public_inputs
        .iter()
        .cloned()
        .map(|public_values| VerifierInput::new(air, public_values))
        .collect()
}

fn decode_and_verify(fixture: &Fixture, blob: &[u8]) -> Result<DecodedProofBlob, String> {
    let decoded = decode_proof_blob_v1(blob).map_err(|err| err.to_string())?;
    let verifier_inputs = verifier_inputs_from_publics(fixture.air, &decoded.public_inputs);
    verify(
        &fixture.config,
        &fixture.vk,
        verifier_inputs,
        &decoded.proof,
    )
    .map_err(|err| format!("verification failed: {err:?}"))?;
    Ok(decoded)
}

#[test]
fn proof_blob_roundtrip_and_strictness() {
    let fixture = build_fixture();

    let blob_a = encode_proof_blob_v1(&fixture.public_inputs, &fixture.proof);
    let blob_b = encode_proof_blob_v1(&fixture.public_inputs, &fixture.proof);
    assert_eq!(blob_a, blob_b, "encoding must be deterministic");

    let decoded = decode_and_verify(&fixture, &blob_a).expect("roundtrip decode+verify failed");
    assert_eq!(decoded.public_inputs, fixture.public_inputs);

    let mut trailing = blob_a.clone();
    trailing.push(0u8);
    assert!(
        decode_proof_blob_v1(&trailing).is_err(),
        "decoder must reject trailing bytes"
    );

    // Replace canonical `air_count = 1` with non-canonical ULEB128 encoding: `0x81 0x00`.
    let mut noncanonical = Vec::with_capacity(blob_a.len() + 1);
    noncanonical.extend_from_slice(&blob_a[..5]);
    noncanonical.extend_from_slice(&[0x81, 0x00]);
    noncanonical.extend_from_slice(&blob_a[6..]);
    assert!(
        decode_proof_blob_v1(&noncanonical).is_err(),
        "decoder must reject non-canonical varuints"
    );
}

#[test]
fn calldata_and_json_mode_contract() {
    let fixture = build_fixture();

    let blob = encode_proof_blob_v1(&fixture.public_inputs, &fixture.proof);
    let calldata = encode_calldata_verify_bytes(&blob);

    assert_eq!(&calldata[..4], &verify_bytes_selector());

    let decoded_blob = decode_verify_bytes_calldata(&calldata).expect("invalid calldata encoding");
    assert_eq!(
        decoded_blob, blob,
        "calldata bytes arg must equal proof blob"
    );

    let json = render_json_payload(&blob, &calldata, false);
    assert!(json.contains("\"schema\":\"p3-hyperplonk-evm-proof-v1\""));
    assert!(json.contains("\"verify_function\":\"verify(bytes)\""));
    assert!(json.contains(&format!("\"proof_bytes_len\":{}", blob.len())));
    assert!(json.contains(&format!("\"calldata_len\":{}", calldata.len())));
}

#[test]
fn tampering_representative_fields_breaks_verification() {
    let fixture = build_fixture();

    let (blob, offsets) = encode_proof_blob_v1_with_offsets(&fixture.public_inputs, &fixture.proof);

    let targets = vec![
        ("commitment", offsets.commitment_offset),
        (
            "initial_ood_answer",
            offsets.first_initial_ood_answer_offset,
        ),
        ("sumcheck_coeff", offsets.first_sumcheck_coeff_offset),
        ("merkle_sibling", offsets.first_merkle_sibling_offset),
        ("final_poly", offsets.first_final_poly_offset),
    ];

    for (name, maybe_offset) in targets {
        let offset = maybe_offset.unwrap_or_else(|| panic!("missing offset for {name}"));
        assert!(offset < blob.len(), "offset for {name} out of bounds");

        let mut tampered = blob.clone();
        tampered[offset] ^= 1;

        match decode_proof_blob_v1(&tampered) {
            Ok(decoded) => {
                let verifier_inputs =
                    verifier_inputs_from_publics(fixture.air, &decoded.public_inputs);
                let ok = verify(
                    &fixture.config,
                    &fixture.vk,
                    verifier_inputs,
                    &decoded.proof,
                )
                .is_ok();
                assert!(!ok, "tampering in {name} unexpectedly still verifies");
            }
            Err(_) => {
                // Strict decoder rejection is also acceptable for tampered payloads.
            }
        }
    }
}
