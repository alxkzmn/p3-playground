use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::iter::repeat_with;
use core::marker::PhantomData;

use itertools::{Itertools, izip};
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::horizontally_truncated::HorizontallyTruncated;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_ml_pcs::{MlPcs, MlQuery};
use p3_symmetric::{CryptographicHasher, Hash as MerkleHash, PseudoCompressionFunction};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info_span;

use whir_p3::errors::WhirError;
use whir_p3::fiat_shamir::domain_separator::DomainSeparator;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::poly::multilinear::MultilinearPoint;
use whir_p3::whir::committer::Witness;
use whir_p3::whir::committer::reader::CommitmentReader;
use whir_p3::whir::constraints::statement::EqStatement;
use whir_p3::whir::parameters::WhirConfig;
use whir_p3::whir::proof::WhirProofKeccak;
use whir_p3::whir::prover::Prover;
use whir_p3::whir::verifier::Verifier;

use crate::pcs::{ConcatMats, ConcatMatsMeta};

const DIGEST_ELEMS: usize = 32; // bytes32

// For Keccak bytes32 digests we use scalar leaves to avoid requiring packed-byte digest types.
type WhirMmcs<Val, Hash, Compression> = MerkleTreeMmcs<Val, u8, Hash, Compression, DIGEST_ELEMS>;

#[derive(Debug)]
pub struct WhirPcsKeccak<Val, Dft, Hash, Compression> {
    dft: Dft,
    whir: whir_p3::parameters::ProtocolParameters<Hash, Compression>,
    _phantom: PhantomData<Val>,
}

impl<Val, Dft, Hash, Compression> WhirPcsKeccak<Val, Dft, Hash, Compression> {
    pub const fn new(dft: Dft, whir: whir_p3::parameters::ProtocolParameters<Hash, Compression>) -> Self {
        Self { dft, whir, _phantom: PhantomData }
    }
}

impl<Val, Dft, Hash, Compression, Challenge, Challenger> MlPcs<Challenge, Challenger>
    for WhirPcsKeccak<Val, Dft, Hash, Compression>
where
    Val: TwoAdicField + PrimeField64 + Ord + Serialize + DeserializeOwned,
    Dft: TwoAdicSubgroupDft<Val>,
    Hash: Clone
        + Sync
        + CryptographicHasher<Val, [u8; DIGEST_ELEMS]>
        + CryptographicHasher<Val::Packing, [u8; DIGEST_ELEMS]>,
    Compression: Clone + Sync + PseudoCompressionFunction<[u8; DIGEST_ELEMS], 2>,
    Challenge: TwoAdicField + ExtensionField<Val> + Serialize + DeserializeOwned,
    Challenger: FieldChallenger<Val>
        + GrindingChallenger<Witness = Val>
        + CanObserve<MerkleHash<Val, u8, DIGEST_ELEMS>>,
    u8: whir_p3::whir::digest::LeafPacking<Val, Packed = u8, LeafPacked = Val>,
    (): whir_p3::whir::digest::ObserveMerkleRoot<Val, u8, DIGEST_ELEMS, Obs = MerkleHash<Val, u8, DIGEST_ELEMS>>,
    [u8; DIGEST_ELEMS]: Serialize + DeserializeOwned,
{
    type Val = Val;
    type Commitment = <WhirMmcs<Val, Hash, Compression> as Mmcs<Val>>::Commitment;
    type ProverData = (
        ConcatMats<Val>,
        RefCell<
            Option<
                <WhirMmcs<Val, Hash, Compression> as Mmcs<Val>>::ProverData<DenseMatrix<Val>>,
            >,
        >,
    );
    type Evaluations<'a> = HorizontallyTruncated<Val, RowMajorMatrixView<'a, Val>>;
    type Proof = Vec<WhirProofKeccak<Val, Challenge>>;
    type Error = WhirError;

    fn commit(
        &self,
        evaluations: Vec<RowMajorMatrix<Self::Val>>,
    ) -> (Self::Commitment, Self::ProverData) {
        let concat_mats = info_span!("concat matrices").in_scope(|| ConcatMats::new(evaluations));
        let num_variables = concat_mats.meta.log_b;

        let config = WhirConfig::<Challenge, Val, Hash, Compression, Challenger>::new(
            num_variables,
            self.whir.clone(),
        );

        let folded_matrix = info_span!("commit: transpose/pad + dft").in_scope(|| {
            let mut mat = RowMajorMatrixView::new(
                &concat_mats.values,
                1 << (num_variables - config.folding_factor.at_round(0)),
            )
            .transpose();

            mat.pad_to_height(
                1 << (num_variables + config.starting_log_inv_rate - config.folding_factor.at_round(0)),
                Val::ZERO,
            );
            self.dft.dft_batch(mat).to_row_major_matrix()
        });

        let mmcs = WhirMmcs::<Val, Hash, Compression>::new(
            self.whir.merkle_hash.clone(),
            self.whir.merkle_compress.clone(),
        );
        let (commitment, merkle_tree) = mmcs.commit_matrix(folded_matrix);
        (commitment, (concat_mats, RefCell::new(Some(merkle_tree))))
    }

    fn get_evaluations<'a>(
        &self,
        (concat_mats, _): &'a Self::ProverData,
        idx: usize,
    ) -> Self::Evaluations<'a> {
        concat_mats.mat(idx)
    }

    fn open(
        &self,
        rounds: Vec<(
            &Self::ProverData,
            Vec<Vec<(MlQuery<Challenge>, Vec<Challenge>)>>,
        )>,
        challenger: &mut Challenger,
    ) -> Self::Proof {
        rounds
            .iter()
            .map(|((concat_mats, merkle_tree), queries_and_evals)| {
                let num_variables = concat_mats.meta.log_b;
                let config = WhirConfig::<Challenge, Val, Hash, Compression, Challenger>::new(
                    num_variables,
                    self.whir.clone(),
                );

                let mut domainsep: DomainSeparator<Challenge, Val> =
                    DomainSeparator::new(Vec::new());
                domainsep.commit_statement::<_, _, _, DIGEST_ELEMS>(&config);
                domainsep.add_whir_proof::<_, _, _, DIGEST_ELEMS>(&config);
                domainsep.observe_domain_separator(challenger);

                let mut proof =
                    WhirProofKeccak::<Val, Challenge>::from_protocol_parameters(&self.whir, num_variables);

                let polynomial = EvaluationsList::new(concat_mats.values.clone());

                // Fill the initial commitment root and observe it (bytes32 root).
                let root = merkle_tree.borrow().as_ref().unwrap().root();
                proof.initial_commitment = *root.as_ref();
                challenger.observe(root);

                // Commitment OOD statements.
                let mut ood_statement = EqStatement::initialize(num_variables);
                (0..config.commitment_ood_samples).for_each(|_| {
                    let u: Challenge = challenger.sample_algebra_element();
                    let point = MultilinearPoint::expand_from_univariate(u, num_variables);
                    let eval = polynomial.evaluate_hypercube_base::<Challenge>(&point);
                    proof.initial_ood_answers.push(eval);
                    challenger.observe_algebra_element(eval);
                    ood_statement.add_evaluated_constraint(point, eval);
                });

                // Sample randomness used to linearly combine columns inside each matrix query.
                let r = repeat_with(|| challenger.sample_algebra_element::<Challenge>())
                    .take(concat_mats.meta.max_log_width())
                    .collect_vec();

                let statement = info_span!("build EqStatement").in_scope(|| {
                    let mut statement = EqStatement::initialize(num_variables);
                    queries_and_evals
                        .iter()
                        .enumerate()
                        .for_each(|(idx, queries_and_evals)| {
                            queries_and_evals.iter().for_each(|(query, evals)| {
                                let (point, sum) =
                                    concat_mats.meta.constraint(idx, query, evals, &r);
                                statement.add_evaluated_constraint(point, sum);
                            })
                        });
                    statement
                });

                let witness = Witness::<Challenge, Val, DenseMatrix<Val>, DIGEST_ELEMS, u8> {
                    polynomial,
                    prover_data: Arc::new(merkle_tree.take().unwrap()),
                    ood_statement,
                };

                info_span!("whir_p3::prove").in_scope(|| {
                    Prover(&config)
                        .prove::<_, DIGEST_ELEMS, u8>(
                            &self.dft,
                            &mut proof,
                            challenger,
                            statement,
                            witness,
                        )
                        .expect("WHIR proving failed");
                });

                proof
            })
            .collect()
    }

    fn verify(
        &self,
        rounds: Vec<(Self::Commitment, Vec<Vec<(MlQuery<Challenge>, Vec<Challenge>)>>)>,
        proofs: &Self::Proof,
        challenger: &mut Challenger,
    ) -> Result<(), Self::Error> {
        izip!(rounds, proofs).try_for_each(|((commitment, round), proof)| {
            let concat_mats_meta = ConcatMatsMeta::new(
                round
                    .iter()
                    .map(|mat| Dimensions {
                        width: mat[0].1.len(),
                        height: 1 << mat[0].0.log_b(),
                    })
                    .collect(),
            );
            let num_variables = concat_mats_meta.log_b;

            let config = WhirConfig::<Challenge, Val, Hash, Compression, Challenger>::new(
                num_variables,
                self.whir.clone(),
            );

            let mut domainsep: DomainSeparator<Challenge, Val> = DomainSeparator::new(Vec::new());
            domainsep.commit_statement::<_, _, _, DIGEST_ELEMS>(&config);
            domainsep.add_whir_proof::<_, _, _, DIGEST_ELEMS>(&config);
            domainsep.observe_domain_separator(challenger);

            let parsed_commitment =
                CommitmentReader::new(&config).parse_commitment::<DIGEST_ELEMS, u8>(proof, challenger);
            debug_assert_eq!(parsed_commitment.root, commitment);

            let r = repeat_with(|| challenger.sample_algebra_element::<Challenge>())
                .take(concat_mats_meta.max_log_width())
                .collect_vec();
            let mut statement = EqStatement::initialize(num_variables);
            round.iter().enumerate().for_each(|(idx, evals)| {
                evals.iter().for_each(|(query, ys)| {
                    let (point, sum) = concat_mats_meta.constraint(idx, query, ys, &r);
                    statement.add_evaluated_constraint(point, sum);
                })
            });

            Verifier::new(&config)
                .verify::<DIGEST_ELEMS, u8>(proof, challenger, &parsed_commitment, statement)
                .map(|_| ())
                .map_err(Into::into)
        })
    }
}


