#[cfg(test)]
use core::fmt;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
#[cfg(test)]
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeField32};
#[cfg(test)]
use p3_hyperplonk::Fraction;
use p3_hyperplonk::{
    AirProof, BatchSumcheckProof, CompressedRoundPoly, FractionalSumProof, HyperPlonkConfig,
    PiopProof, Proof, RoundPoly,
};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_symmetric::CryptographicHasher;
#[cfg(test)]
use p3_whir::digest_bytes32_to_u64;
use p3_whir::{KeccakNodeCompress, KeccakU32BeLeafHasher, WhirPcs, digest_u64_to_bytes32};
#[cfg(test)]
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::proof::{QueryOpening, SumcheckData, WhirProof, WhirRoundProof};

pub const PROOF_BLOB_MAGIC: [u8; 4] = *b"HPK1";
pub const PROOF_BLOB_VERSION: u8 = 1;
pub const JSON_SCHEMA: &str = "p3-hyperplonk-evm-proof-v1";
pub const VERIFY_FUNCTION: &str = "verify(bytes)";

pub type Val = KoalaBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type FieldHash = KeccakU32BeLeafHasher;
pub type Compress = KeccakNodeCompress;
pub type Dft = Radix2DitParallel<Val>;
pub type Pcs = WhirPcs<Val, Dft, FieldHash, Compress, 4>;
pub type Challenger = SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>;
pub type HyperPlonkProofConfig = HyperPlonkConfig<Pcs, Challenge, Challenger>;
pub type HyperPlonkProof = Proof<HyperPlonkProofConfig>;
pub type WhirPcsProof = WhirProof<Val, Challenge, u64, 4>;

#[derive(Debug, Clone, Default)]
pub struct ProofBlobOffsets {
    pub commitment_offset: Option<usize>,
    pub first_initial_ood_answer_offset: Option<usize>,
    pub first_sumcheck_coeff_offset: Option<usize>,
    pub first_merkle_sibling_offset: Option<usize>,
    pub first_final_poly_offset: Option<usize>,
}

#[cfg(test)]
#[derive(Debug)]
pub struct DecodedProofBlob {
    pub public_inputs: Vec<Vec<Val>>,
    pub proof: HyperPlonkProof,
}

#[cfg(test)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecodeError {
    msg: String,
}

#[cfg(test)]
impl DecodeError {
    fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }
}

#[cfg(test)]
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

#[cfg(test)]
impl std::error::Error for DecodeError {}

pub fn encode_proof_blob_v1(public_inputs: &[Vec<Val>], proof: &HyperPlonkProof) -> Vec<u8> {
    encode_proof_blob_v1_with_offsets(public_inputs, proof).0
}

pub fn encode_proof_blob_v1_with_offsets(
    public_inputs: &[Vec<Val>],
    proof: &HyperPlonkProof,
) -> (Vec<u8>, ProofBlobOffsets) {
    let mut writer = BlobWriter::new();
    let mut offsets = ProofBlobOffsets::default();

    writer.write_bytes(&PROOF_BLOB_MAGIC);
    writer.write_u8(PROOF_BLOB_VERSION);

    writer.write_len(public_inputs.len());
    for per_air in public_inputs {
        writer.write_len(per_air.len());
        for &value in per_air {
            writer.write_val(value);
        }
    }

    writer.write_len(proof.log_bs.len());
    for &log_b in &proof.log_bs {
        writer.write_len(log_b);
    }

    offsets.commitment_offset = Some(writer.pos());
    writer.write_digest(proof.commitment.as_ref());

    encode_piop(&mut writer, &proof.piop, &mut offsets);

    writer.write_len(proof.pcs.len());
    for pcs in &proof.pcs {
        encode_whir_proof(&mut writer, pcs, &mut offsets);
    }

    (writer.finish(), offsets)
}

fn encode_piop(
    writer: &mut BlobWriter,
    piop: &PiopProof<Challenge>,
    offsets: &mut ProofBlobOffsets,
) {
    encode_fractional_sum(writer, &piop.fractional_sum, offsets);
    encode_air_proof(writer, &piop.air, offsets);
}

fn encode_fractional_sum(
    writer: &mut BlobWriter,
    proof: &FractionalSumProof<Challenge>,
    offsets: &mut ProofBlobOffsets,
) {
    writer.write_len(proof.sums.len());
    for sums in &proof.sums {
        writer.write_len(sums.len());
        for fraction in sums {
            writer.write_challenge_marked(fraction.numer, &mut offsets.first_sumcheck_coeff_offset);
            writer.write_challenge_marked(fraction.denom, &mut offsets.first_sumcheck_coeff_offset);
        }
    }

    writer.write_len(proof.layers.len());
    for layer in &proof.layers {
        encode_batch_sumcheck_proof(writer, layer, offsets);
    }
}

fn encode_air_proof(
    writer: &mut BlobWriter,
    proof: &AirProof<Challenge>,
    offsets: &mut ProofBlobOffsets,
) {
    writer.write_len(proof.univariate_skips.len());
    for skip in &proof.univariate_skips {
        writer.write_len(skip.skip_rounds);
        encode_round_poly(
            writer,
            &skip.zero_check_round_poly,
            &mut offsets.first_sumcheck_coeff_offset,
        );
        encode_round_poly(
            writer,
            &skip.eval_check_round_poly,
            &mut offsets.first_sumcheck_coeff_offset,
        );
    }

    encode_batch_sumcheck_proof(writer, &proof.regular, offsets);
    encode_batch_sumcheck_proof(writer, &proof.univariate_eval_check, offsets);
}

fn encode_round_poly(
    writer: &mut BlobWriter,
    poly: &RoundPoly<Challenge>,
    marker: &mut Option<usize>,
) {
    writer.write_len(poly.0.len());
    for &coeff in &poly.0 {
        writer.write_challenge_marked(coeff, marker);
    }
}

fn encode_compressed_round_poly(
    writer: &mut BlobWriter,
    poly: &CompressedRoundPoly<Challenge>,
    marker: &mut Option<usize>,
) {
    writer.write_len(poly.0.len());
    for &coeff in &poly.0 {
        writer.write_challenge_marked(coeff, marker);
    }
}

fn encode_batch_sumcheck_proof(
    writer: &mut BlobWriter,
    proof: &BatchSumcheckProof<Challenge>,
    offsets: &mut ProofBlobOffsets,
) {
    writer.write_len(proof.compressed_round_polys.len());
    for poly in &proof.compressed_round_polys {
        encode_compressed_round_poly(writer, poly, &mut offsets.first_sumcheck_coeff_offset);
    }

    writer.write_len(proof.evals.len());
    for evals in &proof.evals {
        writer.write_len(evals.len());
        for &eval in evals {
            writer.write_challenge_marked(eval, &mut offsets.first_sumcheck_coeff_offset);
        }
    }
}

fn encode_whir_proof(
    writer: &mut BlobWriter,
    proof: &WhirPcsProof,
    offsets: &mut ProofBlobOffsets,
) {
    writer.write_digest(&proof.initial_commitment);

    writer.write_len(proof.initial_ood_answers.len());
    for &answer in &proof.initial_ood_answers {
        writer.write_challenge_marked(answer, &mut offsets.first_initial_ood_answer_offset);
    }

    encode_whir_sumcheck(writer, &proof.initial_sumcheck, offsets);

    writer.write_len(proof.rounds.len());
    for round in &proof.rounds {
        encode_whir_round(writer, round, offsets);
    }

    writer.write_option(&proof.final_poly, |writer, final_poly| {
        if offsets.first_final_poly_offset.is_none() && !final_poly.as_slice().is_empty() {
            offsets.first_final_poly_offset = Some(writer.pos());
        }
        writer.write_len(final_poly.as_slice().len());
        for &eval in final_poly.as_slice() {
            writer.write_challenge(eval);
        }
    });

    writer.write_val(proof.final_pow_witness);

    writer.write_len(proof.final_queries.len());
    for query in &proof.final_queries {
        encode_query_opening(writer, query, offsets);
    }

    writer.write_option(&proof.final_sumcheck, |writer, sumcheck| {
        encode_whir_sumcheck(writer, sumcheck, offsets);
    });
}

fn encode_whir_round(
    writer: &mut BlobWriter,
    round: &WhirRoundProof<Val, Challenge, u64, 4>,
    offsets: &mut ProofBlobOffsets,
) {
    writer.write_digest(&round.commitment);

    writer.write_len(round.ood_answers.len());
    for &answer in &round.ood_answers {
        writer.write_challenge_marked(answer, &mut offsets.first_initial_ood_answer_offset);
    }

    writer.write_val(round.pow_witness);

    writer.write_len(round.queries.len());
    for query in &round.queries {
        encode_query_opening(writer, query, offsets);
    }

    encode_whir_sumcheck(writer, &round.sumcheck, offsets);
}

fn encode_whir_sumcheck(
    writer: &mut BlobWriter,
    sumcheck: &SumcheckData<Val, Challenge>,
    offsets: &mut ProofBlobOffsets,
) {
    writer.write_len(sumcheck.polynomial_evaluations.len());
    for coeffs in &sumcheck.polynomial_evaluations {
        writer.write_challenge_marked(coeffs[0], &mut offsets.first_sumcheck_coeff_offset);
        writer.write_challenge_marked(coeffs[1], &mut offsets.first_sumcheck_coeff_offset);
    }

    writer.write_len(sumcheck.pow_witnesses.len());
    for &witness in &sumcheck.pow_witnesses {
        writer.write_val(witness);
    }
}

fn encode_query_opening(
    writer: &mut BlobWriter,
    query: &QueryOpening<Val, Challenge, u64, 4>,
    offsets: &mut ProofBlobOffsets,
) {
    match query {
        QueryOpening::Base { values, proof } => {
            writer.write_u8(0);
            writer.write_len(values.len());
            for &value in values {
                writer.write_val(value);
            }
            writer.write_len(proof.len());
            for sibling in proof {
                if offsets.first_merkle_sibling_offset.is_none() {
                    offsets.first_merkle_sibling_offset = Some(writer.pos());
                }
                writer.write_digest(sibling);
            }
        }
        QueryOpening::Extension { values, proof } => {
            writer.write_u8(1);
            writer.write_len(values.len());
            for &value in values {
                writer.write_challenge(value);
            }
            writer.write_len(proof.len());
            for sibling in proof {
                if offsets.first_merkle_sibling_offset.is_none() {
                    offsets.first_merkle_sibling_offset = Some(writer.pos());
                }
                writer.write_digest(sibling);
            }
        }
    }
}

#[cfg(test)]
pub fn decode_proof_blob_v1(bytes: &[u8]) -> Result<DecodedProofBlob, DecodeError> {
    let mut reader = BlobReader::new(bytes);

    let magic = reader.read_exact::<4>()?;
    if magic != PROOF_BLOB_MAGIC {
        return Err(DecodeError::new("invalid proof blob magic"));
    }

    let version = reader.read_u8()?;
    if version != PROOF_BLOB_VERSION {
        return Err(DecodeError::new("unsupported proof blob version"));
    }

    let air_count = reader.read_len()?;
    let mut public_inputs = Vec::with_capacity(air_count);
    for _ in 0..air_count {
        let n_public_values = reader.read_len()?;
        let mut values = Vec::with_capacity(n_public_values);
        for _ in 0..n_public_values {
            values.push(reader.read_val()?);
        }
        public_inputs.push(values);
    }

    let n_log_bs = reader.read_len()?;
    let mut log_bs = Vec::with_capacity(n_log_bs);
    for _ in 0..n_log_bs {
        log_bs.push(reader.read_len()?);
    }

    let commitment = reader.read_digest()?.into();
    let piop = decode_piop(&mut reader)?;

    let n_pcs = reader.read_len()?;
    let mut pcs = Vec::with_capacity(n_pcs);
    for _ in 0..n_pcs {
        pcs.push(decode_whir_proof(&mut reader)?);
    }

    if !reader.is_eof() {
        return Err(DecodeError::new("trailing bytes after proof payload"));
    }

    Ok(DecodedProofBlob {
        public_inputs,
        proof: HyperPlonkProof {
            log_bs,
            commitment,
            piop,
            pcs,
        },
    })
}

#[cfg(test)]
fn decode_piop(reader: &mut BlobReader<'_>) -> Result<PiopProof<Challenge>, DecodeError> {
    Ok(PiopProof {
        fractional_sum: decode_fractional_sum(reader)?,
        air: decode_air_proof(reader)?,
    })
}

#[cfg(test)]
fn decode_fractional_sum(
    reader: &mut BlobReader<'_>,
) -> Result<FractionalSumProof<Challenge>, DecodeError> {
    let n_sums = reader.read_len()?;
    let mut sums = Vec::with_capacity(n_sums);
    for _ in 0..n_sums {
        let n_fractions = reader.read_len()?;
        let mut fractions = Vec::with_capacity(n_fractions);
        for _ in 0..n_fractions {
            fractions.push(Fraction {
                numer: reader.read_challenge()?,
                denom: reader.read_challenge()?,
            });
        }
        sums.push(fractions);
    }

    let n_layers = reader.read_len()?;
    let mut layers = Vec::with_capacity(n_layers);
    for _ in 0..n_layers {
        layers.push(decode_batch_sumcheck_proof(reader)?);
    }

    Ok(FractionalSumProof { sums, layers })
}

#[cfg(test)]
fn decode_air_proof(reader: &mut BlobReader<'_>) -> Result<AirProof<Challenge>, DecodeError> {
    let n_univariate_skips = reader.read_len()?;
    let mut univariate_skips = Vec::with_capacity(n_univariate_skips);
    for _ in 0..n_univariate_skips {
        univariate_skips.push(p3_hyperplonk::AirUnivariateSkipProof {
            skip_rounds: reader.read_len()?,
            zero_check_round_poly: decode_round_poly(reader)?,
            eval_check_round_poly: decode_round_poly(reader)?,
        });
    }

    Ok(AirProof {
        univariate_skips,
        regular: decode_batch_sumcheck_proof(reader)?,
        univariate_eval_check: decode_batch_sumcheck_proof(reader)?,
    })
}

#[cfg(test)]
fn decode_round_poly(reader: &mut BlobReader<'_>) -> Result<RoundPoly<Challenge>, DecodeError> {
    let n_coeffs = reader.read_len()?;
    let mut coeffs = Vec::with_capacity(n_coeffs);
    for _ in 0..n_coeffs {
        coeffs.push(reader.read_challenge()?);
    }
    Ok(RoundPoly(coeffs))
}

#[cfg(test)]
fn decode_compressed_round_poly(
    reader: &mut BlobReader<'_>,
) -> Result<CompressedRoundPoly<Challenge>, DecodeError> {
    let n_coeffs = reader.read_len()?;
    let mut coeffs = Vec::with_capacity(n_coeffs);
    for _ in 0..n_coeffs {
        coeffs.push(reader.read_challenge()?);
    }
    Ok(CompressedRoundPoly(coeffs))
}

#[cfg(test)]
fn decode_batch_sumcheck_proof(
    reader: &mut BlobReader<'_>,
) -> Result<BatchSumcheckProof<Challenge>, DecodeError> {
    let n_round_polys = reader.read_len()?;
    let mut compressed_round_polys = Vec::with_capacity(n_round_polys);
    for _ in 0..n_round_polys {
        compressed_round_polys.push(decode_compressed_round_poly(reader)?);
    }

    let n_eval_sets = reader.read_len()?;
    let mut evals = Vec::with_capacity(n_eval_sets);
    for _ in 0..n_eval_sets {
        let n_evals = reader.read_len()?;
        let mut eval_set = Vec::with_capacity(n_evals);
        for _ in 0..n_evals {
            eval_set.push(reader.read_challenge()?);
        }
        evals.push(eval_set);
    }

    Ok(BatchSumcheckProof {
        compressed_round_polys,
        evals,
    })
}

#[cfg(test)]
fn decode_whir_proof(reader: &mut BlobReader<'_>) -> Result<WhirPcsProof, DecodeError> {
    let initial_commitment = reader.read_digest()?;

    let n_initial_ood_answers = reader.read_len()?;
    let mut initial_ood_answers = Vec::with_capacity(n_initial_ood_answers);
    for _ in 0..n_initial_ood_answers {
        initial_ood_answers.push(reader.read_challenge()?);
    }

    let initial_sumcheck = decode_whir_sumcheck(reader)?;

    let n_rounds = reader.read_len()?;
    let mut rounds = Vec::with_capacity(n_rounds);
    for _ in 0..n_rounds {
        rounds.push(decode_whir_round(reader)?);
    }

    let final_poly = reader.read_option(|reader| {
        let n_evals = reader.read_len()?;
        if !n_evals.is_power_of_two() {
            return Err(DecodeError::new("final_poly length must be a power of two"));
        }
        let mut evals = Vec::with_capacity(n_evals);
        for _ in 0..n_evals {
            evals.push(reader.read_challenge()?);
        }
        Ok(EvaluationsList::new(evals))
    })?;

    let final_pow_witness = reader.read_val()?;

    let n_final_queries = reader.read_len()?;
    let mut final_queries = Vec::with_capacity(n_final_queries);
    for _ in 0..n_final_queries {
        final_queries.push(decode_query_opening(reader)?);
    }

    let final_sumcheck = reader.read_option(decode_whir_sumcheck)?;

    Ok(WhirPcsProof {
        initial_commitment,
        initial_ood_answers,
        initial_sumcheck,
        rounds,
        final_poly,
        final_pow_witness,
        final_queries,
        final_sumcheck,
    })
}

#[cfg(test)]
fn decode_whir_round(
    reader: &mut BlobReader<'_>,
) -> Result<WhirRoundProof<Val, Challenge, u64, 4>, DecodeError> {
    let commitment = reader.read_digest()?;

    let n_ood_answers = reader.read_len()?;
    let mut ood_answers = Vec::with_capacity(n_ood_answers);
    for _ in 0..n_ood_answers {
        ood_answers.push(reader.read_challenge()?);
    }

    let pow_witness = reader.read_val()?;

    let n_queries = reader.read_len()?;
    let mut queries = Vec::with_capacity(n_queries);
    for _ in 0..n_queries {
        queries.push(decode_query_opening(reader)?);
    }

    let sumcheck = decode_whir_sumcheck(reader)?;

    Ok(WhirRoundProof {
        commitment,
        ood_answers,
        pow_witness,
        queries,
        sumcheck,
    })
}

#[cfg(test)]
fn decode_whir_sumcheck(
    reader: &mut BlobReader<'_>,
) -> Result<SumcheckData<Val, Challenge>, DecodeError> {
    let n_poly_evals = reader.read_len()?;
    let mut polynomial_evaluations = Vec::with_capacity(n_poly_evals);
    for _ in 0..n_poly_evals {
        let c0 = reader.read_challenge()?;
        let c2 = reader.read_challenge()?;
        polynomial_evaluations.push([c0, c2]);
    }

    let n_pow_witnesses = reader.read_len()?;
    let mut pow_witnesses = Vec::with_capacity(n_pow_witnesses);
    for _ in 0..n_pow_witnesses {
        pow_witnesses.push(reader.read_val()?);
    }

    Ok(SumcheckData {
        polynomial_evaluations,
        pow_witnesses,
    })
}

#[cfg(test)]
fn decode_query_opening(
    reader: &mut BlobReader<'_>,
) -> Result<QueryOpening<Val, Challenge, u64, 4>, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        0 => {
            let n_values = reader.read_len()?;
            let mut values = Vec::with_capacity(n_values);
            for _ in 0..n_values {
                values.push(reader.read_val()?);
            }
            let n_siblings = reader.read_len()?;
            let mut proof = Vec::with_capacity(n_siblings);
            for _ in 0..n_siblings {
                proof.push(reader.read_digest()?);
            }
            Ok(QueryOpening::Base { values, proof })
        }
        1 => {
            let n_values = reader.read_len()?;
            let mut values = Vec::with_capacity(n_values);
            for _ in 0..n_values {
                values.push(reader.read_challenge()?);
            }
            let n_siblings = reader.read_len()?;
            let mut proof = Vec::with_capacity(n_siblings);
            for _ in 0..n_siblings {
                proof.push(reader.read_digest()?);
            }
            Ok(QueryOpening::Extension { values, proof })
        }
        _ => Err(DecodeError::new("unknown query opening tag")),
    }
}

pub fn verify_bytes_selector() -> [u8; 4] {
    let hash: [u8; 32] = Keccak256Hash.hash_iter(VERIFY_FUNCTION.as_bytes().iter().copied());
    [hash[0], hash[1], hash[2], hash[3]]
}

pub fn encode_calldata_verify_bytes(proof_blob: &[u8]) -> Vec<u8> {
    let selector = verify_bytes_selector();
    let encoded_args = abi_encode_single_bytes(proof_blob);
    let mut out = Vec::with_capacity(4 + encoded_args.len());
    out.extend_from_slice(&selector);
    out.extend_from_slice(&encoded_args);
    out
}

#[cfg(test)]
pub fn decode_verify_bytes_calldata(calldata: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if calldata.len() < 4 + 64 {
        return Err(DecodeError::new("calldata too short"));
    }

    if calldata[..4] != verify_bytes_selector() {
        return Err(DecodeError::new("invalid verify(bytes) selector"));
    }

    let args = &calldata[4..];
    let offset = decode_abi_word_usize(&args[..32])?;
    if offset != 32 {
        return Err(DecodeError::new(
            "invalid ABI offset for single bytes argument",
        ));
    }

    let length = decode_abi_word_usize(&args[32..64])?;
    let data_start: usize = 64;
    let data_end = data_start
        .checked_add(length)
        .ok_or_else(|| DecodeError::new("ABI length overflow"))?;
    if data_end > args.len() {
        return Err(DecodeError::new("ABI bytes length out of bounds"));
    }

    let padded_end = data_start
        .checked_add(pad32(length))
        .ok_or_else(|| DecodeError::new("ABI padded length overflow"))?;
    if padded_end != args.len() {
        return Err(DecodeError::new("unexpected trailing data in calldata"));
    }

    if args[data_end..].iter().any(|&b| b != 0) {
        return Err(DecodeError::new("non-zero ABI padding"));
    }

    Ok(args[data_start..data_end].to_vec())
}

pub fn render_json_payload(proof_blob: &[u8], calldata: &[u8], pretty: bool) -> String {
    let selector = verify_bytes_selector();
    let selector_hex = hex_prefixed(&selector);
    let proof_hex = hex_prefixed(proof_blob);
    let calldata_hex = hex_prefixed(calldata);

    if pretty {
        format!(
            "{{\n  \"schema\": \"{}\",\n  \"verify_function\": \"{}\",\n  \"selector\": \"{}\",\n  \"proof_bytes\": \"{}\",\n  \"proof_bytes_len\": {},\n  \"calldata\": \"{}\",\n  \"calldata_len\": {}\n}}\n",
            JSON_SCHEMA,
            VERIFY_FUNCTION,
            selector_hex,
            proof_hex,
            proof_blob.len(),
            calldata_hex,
            calldata.len(),
        )
    } else {
        format!(
            "{{\"schema\":\"{}\",\"verify_function\":\"{}\",\"selector\":\"{}\",\"proof_bytes\":\"{}\",\"proof_bytes_len\":{},\"calldata\":\"{}\",\"calldata_len\":{}}}",
            JSON_SCHEMA,
            VERIFY_FUNCTION,
            selector_hex,
            proof_hex,
            proof_blob.len(),
            calldata_hex,
            calldata.len(),
        )
    }
}

pub fn hex_prefixed(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

struct BlobWriter {
    bytes: Vec<u8>,
}

impl BlobWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn pos(&self) -> usize {
        self.bytes.len()
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn write_u8(&mut self, v: u8) {
        self.bytes.push(v);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn write_len(&mut self, value: usize) {
        encode_varuint(value, &mut self.bytes);
    }

    fn write_val(&mut self, value: Val) {
        self.bytes
            .extend_from_slice(&value.as_canonical_u32().to_be_bytes());
    }

    fn write_challenge(&mut self, value: Challenge) {
        for limb in Challenge::flatten_to_base(vec![value]) {
            self.write_val(limb);
        }
    }

    fn write_challenge_marked(&mut self, value: Challenge, offset: &mut Option<usize>) {
        if offset.is_none() {
            *offset = Some(self.pos());
        }
        self.write_challenge(value);
    }

    fn write_digest(&mut self, digest: &[u64; 4]) {
        let bytes32 = digest_u64_to_bytes32(digest);
        self.bytes.extend_from_slice(&bytes32);
    }

    fn write_option<T, F>(&mut self, value: &Option<T>, mut write_some: F)
    where
        F: FnMut(&mut BlobWriter, &T),
    {
        match value {
            None => self.write_u8(0),
            Some(v) => {
                self.write_u8(1);
                write_some(self, v);
            }
        }
    }
}

#[cfg(test)]
struct BlobReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[cfg(test)]
impl<'a> BlobReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        if self.pos + N > self.bytes.len() {
            return Err(DecodeError::new("unexpected end of input"));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        if self.pos >= self.bytes.len() {
            return Err(DecodeError::new("unexpected end of input"));
        }
        let out = self.bytes[self.pos];
        self.pos += 1;
        Ok(out)
    }

    fn read_len(&mut self) -> Result<usize, DecodeError> {
        let start = self.pos;

        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            if shift >= 64 {
                return Err(DecodeError::new("varuint overflow"));
            }

            let byte = self.read_u8()?;
            let payload = (byte & 0x7f) as u64;
            result |= payload << shift;

            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }

        if result > usize::MAX as u64 {
            return Err(DecodeError::new("length does not fit in usize"));
        }

        let value = result as usize;
        let mut canonical = Vec::new();
        encode_varuint(value, &mut canonical);
        if self.bytes[start..self.pos] != canonical {
            return Err(DecodeError::new("non-canonical varuint encoding"));
        }

        Ok(value)
    }

    fn read_val(&mut self) -> Result<Val, DecodeError> {
        let bytes = self.read_exact::<4>()?;
        Ok(Val::from_u32(u32::from_be_bytes(bytes)))
    }

    fn read_challenge(&mut self) -> Result<Challenge, DecodeError> {
        let limbs = [
            self.read_val()?,
            self.read_val()?,
            self.read_val()?,
            self.read_val()?,
        ];
        Ok(Challenge::from_basis_coefficients_fn(|idx| limbs[idx]))
    }

    fn read_digest(&mut self) -> Result<[u64; 4], DecodeError> {
        let bytes32 = self.read_exact::<32>()?;
        Ok(digest_bytes32_to_u64(&bytes32))
    }

    fn read_option<T, F>(&mut self, mut read_some: F) -> Result<Option<T>, DecodeError>
    where
        F: FnMut(&mut BlobReader<'_>) -> Result<T, DecodeError>,
    {
        match self.read_u8()? {
            0 => Ok(None),
            1 => read_some(self).map(Some),
            _ => Err(DecodeError::new("unknown option tag")),
        }
    }
}

fn encode_varuint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            break;
        }
        out.push(low | 0x80);
    }
}

fn abi_encode_single_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + pad32(bytes.len()));

    out.extend_from_slice(&encode_abi_word_usize(32));
    out.extend_from_slice(&encode_abi_word_usize(bytes.len()));
    out.extend_from_slice(bytes);
    out.resize(64 + pad32(bytes.len()), 0);

    out
}

fn encode_abi_word_usize(value: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&(value as u64).to_be_bytes());
    out
}

#[cfg(test)]
fn decode_abi_word_usize(bytes: &[u8]) -> Result<usize, DecodeError> {
    if bytes.len() != 32 {
        return Err(DecodeError::new("ABI word must be exactly 32 bytes"));
    }

    if bytes[..24].iter().any(|&b| b != 0) {
        return Err(DecodeError::new(
            "ABI word exceeds usize range (high bytes must be zero)",
        ));
    }

    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[24..]);
    let value = u64::from_be_bytes(low);
    if value > usize::MAX as u64 {
        return Err(DecodeError::new("ABI word does not fit usize"));
    }
    Ok(value as usize)
}

fn pad32(len: usize) -> usize {
    let rem = len % 32;
    if rem == 0 { len } else { len + (32 - rem) }
}
