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
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::proof::SumcheckData;

#[path = "../src/evm_codec.rs"]
#[allow(dead_code)]
mod evm_codec;

use evm_codec::{
    Challenge, DecodedProofBlob, HyperPlonkProof, Val, decode_proof_blob_v1,
    decode_proof_blob_v1_with_context, decode_verify_bytes_calldata, derive_v2_decode_context,
    encode_calldata_verify_bytes, encode_proof_blob_v1, encode_proof_blob_v2,
    encode_proof_blob_v2_with_offsets, render_json_payload, verify_bytes_selector,
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
    let context = derive_v2_decode_context(&fixture.proof).map_err(|err| err.to_string())?;
    let decoded =
        decode_proof_blob_v1_with_context(blob, Some(&context)).map_err(|err| err.to_string())?;
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

    let blob_a = encode_proof_blob_v2(&fixture.public_inputs, &fixture.proof);
    let blob_b = encode_proof_blob_v2(&fixture.public_inputs, &fixture.proof);
    assert_eq!(blob_a, blob_b, "encoding must be deterministic");

    let decoded = decode_and_verify(&fixture, &blob_a).expect("roundtrip decode+verify failed");
    assert_eq!(decoded.public_inputs, fixture.public_inputs);

    let mut trailing = blob_a.clone();
    trailing.push(0u8);
    let context =
        derive_v2_decode_context(&fixture.proof).expect("shape context derivation failed");
    assert!(
        decode_proof_blob_v1_with_context(&trailing, Some(&context)).is_err(),
        "decoder must reject trailing bytes"
    );

    // Replace canonical `air_count = 1` with non-canonical ULEB128 encoding: `0x81 0x00`.
    let mut noncanonical = Vec::with_capacity(blob_a.len() + 1);
    noncanonical.extend_from_slice(&blob_a[..5]);
    noncanonical.extend_from_slice(&[0x81, 0x00]);
    noncanonical.extend_from_slice(&blob_a[6..]);
    assert!(
        decode_proof_blob_v1_with_context(&noncanonical, Some(&context)).is_err(),
        "decoder must reject non-canonical varuints"
    );
}

#[test]
fn calldata_and_json_mode_contract() {
    let fixture = build_fixture();

    let blob = encode_proof_blob_v2(&fixture.public_inputs, &fixture.proof);
    let calldata = encode_calldata_verify_bytes(&blob);

    assert_eq!(&calldata[..4], &verify_bytes_selector());

    let decoded_blob = decode_verify_bytes_calldata(&calldata).expect("invalid calldata encoding");
    assert_eq!(
        decoded_blob, blob,
        "calldata bytes arg must equal proof blob"
    );

    let json = render_json_payload(&blob, &calldata, false);
    assert!(json.contains("\"schema\":\"p3-hyperplonk-evm-proof-v2\""));
    assert!(json.contains("\"verify_function\":\"verify(bytes)\""));
    assert!(json.contains(&format!(
        "\"keccak_mode\":\"{}\"",
        evm_codec::keccak_mode_label()
    )));
    assert!(json.contains("\"hash_counts_prover\":"));
    assert!(json.contains("\"hash_counts_verifier\":"));
    assert!(json.contains("\"hash_counts_total\":"));
    assert!(json.contains(&format!("\"proof_bytes_len\":{}", blob.len())));
    assert!(json.contains(&format!("\"calldata_len\":{}", calldata.len())));
}

#[test]
fn tampering_representative_fields_breaks_verification() {
    let fixture = build_fixture();

    let (blob, offsets) = encode_proof_blob_v2_with_offsets(&fixture.public_inputs, &fixture.proof);

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

        let context =
            derive_v2_decode_context(&fixture.proof).expect("shape context derivation failed");
        match decode_proof_blob_v1_with_context(&tampered, Some(&context)) {
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

#[test]
fn option_roundtrip_stability_for_present_and_absent_sections_hyperplonk() {
    let fixture = build_fixture();
    let baseline_blob = encode_proof_blob_v2(&fixture.public_inputs, &fixture.proof);
    let baseline_context =
        derive_v2_decode_context(&fixture.proof).expect("shape context derivation failed");

    let mut with_options =
        decode_proof_blob_v1_with_context(&baseline_blob, Some(&baseline_context))
            .expect("baseline decode failed");
    for pcs in &mut with_options.proof.pcs {
        pcs.final_poly = Some(EvaluationsList::new(vec![Challenge::ZERO, Challenge::ONE]));
        pcs.final_sumcheck = Some(SumcheckData {
            polynomial_evaluations: vec![[Challenge::ZERO, Challenge::ONE]],
            pow_witnesses: vec![Val::ZERO],
        });
    }

    let with_options_blob = encode_proof_blob_v2(&with_options.public_inputs, &with_options.proof);
    let with_options_context =
        derive_v2_decode_context(&with_options.proof).expect("shape context derivation failed");
    let with_options_decoded =
        decode_proof_blob_v1_with_context(&with_options_blob, Some(&with_options_context))
            .expect("decode with options failed");
    assert!(
        with_options_decoded
            .proof
            .pcs
            .iter()
            .all(|pcs| pcs.final_poly.is_some())
    );
    assert!(
        with_options_decoded
            .proof
            .pcs
            .iter()
            .all(|pcs| pcs.final_sumcheck.is_some())
    );
    let with_options_reencoded = encode_proof_blob_v2(
        &with_options_decoded.public_inputs,
        &with_options_decoded.proof,
    );
    assert_eq!(with_options_reencoded, with_options_blob);

    let mut without_options =
        decode_proof_blob_v1_with_context(&baseline_blob, Some(&baseline_context))
            .expect("baseline decode for none failed");
    for pcs in &mut without_options.proof.pcs {
        pcs.final_poly = None;
        pcs.final_sumcheck = None;
    }

    let without_options_blob =
        encode_proof_blob_v2(&without_options.public_inputs, &without_options.proof);
    let without_options_context =
        derive_v2_decode_context(&without_options.proof).expect("shape context derivation failed");
    let without_options_decoded =
        decode_proof_blob_v1_with_context(&without_options_blob, Some(&without_options_context))
            .expect("decode without options failed");
    assert!(
        without_options_decoded
            .proof
            .pcs
            .iter()
            .all(|pcs| pcs.final_poly.is_none())
    );
    assert!(
        without_options_decoded
            .proof
            .pcs
            .iter()
            .all(|pcs| pcs.final_sumcheck.is_none())
    );
    let without_options_reencoded = encode_proof_blob_v2(
        &without_options_decoded.public_inputs,
        &without_options_decoded.proof,
    );
    assert_eq!(without_options_reencoded, without_options_blob);
}

#[test]
fn decode_verify_bytes_calldata_rejects_trailing_data() {
    let fixture = build_fixture();
    let blob = encode_proof_blob_v2(&fixture.public_inputs, &fixture.proof);
    let mut calldata = encode_calldata_verify_bytes(&blob);
    calldata.extend_from_slice(&[0u8, 1u8, 2u8]);

    assert!(
        decode_verify_bytes_calldata(&calldata).is_err(),
        "decoder must reject trailing calldata bytes"
    );
}

#[test]
fn v1_legacy_blob_decodes_and_verifies() {
    let fixture = build_fixture();
    let blob = encode_proof_blob_v1(&fixture.public_inputs, &fixture.proof);
    let decoded = decode_proof_blob_v1(&blob).expect("v1 blob should decode without context");
    let verifier_inputs = verifier_inputs_from_publics(fixture.air, &decoded.public_inputs);
    verify(
        &fixture.config,
        &fixture.vk,
        verifier_inputs,
        &decoded.proof,
    )
    .expect("v1 decoded proof should verify");
}

#[test]
fn v2_compact_blob_is_smaller_than_v1_for_fixture() {
    let fixture = build_fixture();
    let blob_v2 = encode_proof_blob_v2(&fixture.public_inputs, &fixture.proof);
    let blob_v1 = encode_proof_blob_v1(&fixture.public_inputs, &fixture.proof);
    assert!(
        blob_v2.len() < blob_v1.len(),
        "expected v2 blob ({}) to be smaller than v1 ({})",
        blob_v2.len(),
        blob_v1.len()
    );

    let calldata_v2 = encode_calldata_verify_bytes(&blob_v2);
    let calldata_v1 = encode_calldata_verify_bytes(&blob_v1);
    assert!(
        calldata_v2.len() < calldata_v1.len(),
        "expected v2 calldata ({}) to be smaller than v1 ({})",
        calldata_v2.len(),
        calldata_v1.len()
    );
}
