use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::Reverse;
use core::iter::repeat_with;
use core::marker::PhantomData;
use core::mem::replace;
use core::ops::Range;

use itertools::{Itertools, chain, cloned, izip, rev};
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PrimeField64, TwoAdicField, dot_product};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::horizontally_truncated::HorizontallyTruncated;
use p3_matrix::{Dimensions, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_ml_pcs::{MlPcs, MlQuery, eq_poly};
use p3_symmetric::{CryptographicHasher, Hash as SymHash, PseudoCompressionFunction};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info_span;
use whir_p3::fiat_shamir::domain_separator::DomainSeparator;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::poly::multilinear::MultilinearPoint;
use whir_p3::whir::committer::Witness;
use whir_p3::whir::committer::reader::CommitmentReader;
use whir_p3::whir::parameters::WhirConfig;
use whir_p3::whir::proof::{InitialPhase, SumcheckData, WhirProof};
use whir_p3::whir::prover::Prover;
use whir_p3::whir::verifier::Verifier;
use whir_p3::whir::verifier::errors::VerifierError;

use crate::linear_constraints::LinearEqStatement;

type WhirMmcs<Val, Hash, Compression, const DIGEST_ELEMS: usize> = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compression,
    DIGEST_ELEMS,
>;

type WhirMmcsKeccak<Val, Hash, Compression> = MerkleTreeMmcs<Val, u64, Hash, Compression, 4>;

/// Marker type selecting the default (field-hash) Merkle commitment flavor.
#[derive(Debug, Clone, Copy)]
pub struct FieldHashFlavor;

/// Marker type selecting the Keccak bytes32 Merkle commitment flavor.
#[derive(Debug, Clone, Copy)]
pub struct KeccakFlavor;

#[derive(Debug)]
pub struct WhirPcs<Val, Dft, Hash, Compression, const DIGEST_ELEMS: usize, Flavor = FieldHashFlavor>
{
    dft: Dft,
    whir: whir_p3::parameters::ProtocolParameters<Hash, Compression>,
    _flavor: PhantomData<Flavor>,
    _phantom: PhantomData<Val>,
}

impl<Val, Dft, Hash, Compression, const DIGEST_ELEMS: usize, Flavor>
    WhirPcs<Val, Dft, Hash, Compression, DIGEST_ELEMS, Flavor>
{
    pub const fn new(
        dft: Dft,
        whir: whir_p3::parameters::ProtocolParameters<Hash, Compression>,
    ) -> Self {
        Self {
            dft,
            whir,
            _flavor: PhantomData,
            _phantom: PhantomData,
        }
    }
}

impl<Val, Dft, Hash, Compression, Challenge, Challenger, const DIGEST_ELEMS: usize>
    MlPcs<Challenge, Challenger>
    for WhirPcs<Val, Dft, Hash, Compression, DIGEST_ELEMS, FieldHashFlavor>
where
    Val: TwoAdicField + PrimeField64 + Ord + Serialize + DeserializeOwned,
    <Val as Field>::Packing: Eq,
    Dft: TwoAdicSubgroupDft<Val>,
    Hash: Clone
        + Sync
        + CryptographicHasher<Val, [Val; DIGEST_ELEMS]>
        + CryptographicHasher<Val::Packing, [Val::Packing; DIGEST_ELEMS]>,
    Compression: Clone
        + Sync
        + PseudoCompressionFunction<[Val; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[Val::Packing; DIGEST_ELEMS], 2>,
    Challenge: TwoAdicField + ExtensionField<Val> + Serialize + DeserializeOwned,
    Challenger: FieldChallenger<Val>
        + GrindingChallenger<Witness = Val>
        + CanObserve<SymHash<Val, Val, DIGEST_ELEMS>>,
    [Val; DIGEST_ELEMS]: Serialize + DeserializeOwned,
{
    type Val = Val;
    type Commitment = <WhirMmcs<Val, Hash, Compression, DIGEST_ELEMS> as Mmcs<Val>>::Commitment;
    type ProverData = (
        ConcatMats<Val>,
        RefCell<
            Option<
                <WhirMmcs<Val, Hash, Compression, DIGEST_ELEMS> as Mmcs<Val>>::ProverData<
                    DenseMatrix<Val>,
                >,
            >,
        >,
    );
    type Evaluations<'a> = HorizontallyTruncated<Val, RowMajorMatrixView<'a, Val>>;
    type Proof = Vec<WhirProof<Val, Challenge, Val, DIGEST_ELEMS>>;
    type Error = VerifierError;

    fn commit(
        &self,
        evaluations: Vec<RowMajorMatrix<Self::Val>>,
    ) -> (Self::Commitment, Self::ProverData) {
        // Concat matrices into single polynomial.
        let concat_mats = info_span!("concat matrices").in_scope(|| ConcatMats::new(evaluations));
        let num_variables = concat_mats.meta.log_b;

        // Use WHIR's padding + DFT layout so that proof generation can reuse the same Merkle tree.
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
                1 << (num_variables + config.starting_log_inv_rate
                    - config.folding_factor.at_round(0)),
                Val::ZERO,
            );
            self.dft.dft_batch(mat).to_row_major_matrix()
        });

        let mmcs = WhirMmcs::<Val, Hash, Compression, DIGEST_ELEMS>::new(
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
        // For each round,
        rounds: Vec<(
            &Self::ProverData,
            // for each matrix,
            Vec<
                // for each query:
                Vec<(
                    // the query,
                    MlQuery<Challenge>,
                    // values at the query
                    Vec<Challenge>,
                )>,
            >,
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

                // Fix the Fiat-Shamir transcript pattern for this proof.
                let mut domainsep: DomainSeparator<Challenge, Val> =
                    DomainSeparator::new(Vec::new());
                domainsep.commit_statement::<_, _, _, DIGEST_ELEMS>(&config);
                domainsep.add_whir_proof::<_, _, _, DIGEST_ELEMS>(&config);
                domainsep.observe_domain_separator(challenger);

                // Prepare proof container and witness pieces.
                let mut proof =
                    WhirProof::<Val, Challenge, Val, DIGEST_ELEMS>::from_protocol_parameters(
                    &self.whir,
                    num_variables,
                );

                let polynomial = EvaluationsList::new(concat_mats.values.clone());

                // Fill the initial commitment root and observe it (matches verifier parsing logic).
                let root = merkle_tree.borrow().as_ref().unwrap().root();
                proof.initial_commitment = *root.as_ref();
                challenger.observe(root);

                // Commitment OOD statements (points are sampled from the challenger, then answers observed).
                let mut ood_statement = LinearEqStatement::initialize(num_variables);
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

                let eq_rs = concat_mats
                    .meta
                    .eq_r_per_matrix::<Challenge>(&r);
                let statement = info_span!("build EqStatement").in_scope(|| {
                    let mut statement = LinearEqStatement::initialize(num_variables);
                    queries_and_evals
                        .iter()
                        .enumerate()
                        .for_each(|(idx, queries_and_evals)| {
                            queries_and_evals.iter().for_each(|(query, evals)| {
                                let (constraint, sum) = concat_mats.meta.constraint_with_eq_r(
                                    idx,
                                    query,
                                    evals,
                                    &r,
                                    &eq_rs[idx],
                                );
                                match constraint {
                                    ConcatConstraint::Point(point) => {
                                        statement.add_evaluated_constraint(point, sum);
                                    }
                                    ConcatConstraint::TensorProduct {
                                        range_start,
                                        log_range_len,
                                        row_weights,
                                        col_weights,
                                    } => {
                                        statement.add_tensor_product_constraint(
                                            range_start,
                                            log_range_len,
                                            row_weights,
                                            col_weights,
                                            sum,
                                        );
                                    }
                                }
                            })
                        });
                    statement
                });

                // NOTE: Explicit linear functionals (e.g. `EqRotateRight`) are currently not
                // compatible with the optimized initial phases (univariate-skip, SVO).
                // If we produced any linear constraints, force the classic `WithStatement` path.
                if statement.has_linear_constraints() {
                    match proof.initial_phase {
                        InitialPhase::WithStatementSkip(_)
                        | InitialPhase::WithStatementSvo { .. } => {
                            proof.initial_phase = InitialPhase::WithStatement {
                                sumcheck: SumcheckData::default(),
                            };
                        }
                        InitialPhase::WithStatement { .. }
                        | InitialPhase::WithoutStatement { .. } => {}
                    }
                }
                debug_assert!(matches!(
                    proof.initial_phase,
                    InitialPhase::WithStatement { .. }
                ));

                let witness = Witness {
                    polynomial,
                    prover_data: Arc::new(merkle_tree.take().unwrap()),
                    ood_statement: ood_statement.into_eq_statement(),
                };

                info_span!("whir_p3::prove").in_scope(|| {
                    let statement = statement.into_eq_statement();
                    Prover(&config)
                        .prove::<_, <Val as Field>::Packing, Val, <Val as Field>::Packing, DIGEST_ELEMS>(
                            &self.dft,
                            &mut proof,
                            challenger,
                            statement,
                            witness,
                        )
                        .expect("WHIR proving failed");
                });

                debug_assert!(matches!(
                    proof.initial_phase,
                    InitialPhase::WithStatement { .. }
                ));

                proof
            })
            .collect()
    }

    fn verify(
        &self,
        // For each round:
        rounds: Vec<(
            Self::Commitment,
            // for each matrix:
            Vec<
                // for each query:
                Vec<(
                    // the query,
                    MlQuery<Challenge>,
                    // values at the query
                    Vec<Challenge>,
                )>,
            >,
        )>,
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

            // Fix the Fiat-Shamir transcript pattern for this proof.
            let mut domainsep: DomainSeparator<Challenge, Val> = DomainSeparator::new(Vec::new());
            domainsep.commit_statement::<_, _, _, DIGEST_ELEMS>(&config);
            domainsep.add_whir_proof::<_, _, _, DIGEST_ELEMS>(&config);
            domainsep.observe_domain_separator(challenger);

            // Parse commitment root + OOD statement from transcript (matches prover observation order).
            let parsed_commitment = CommitmentReader::new(&config)
                .parse_commitment::<Val, DIGEST_ELEMS>(proof, challenger);
            debug_assert_eq!(parsed_commitment.root, commitment);

            // Sample the same column-combination randomness and rebuild the same statement.
            let r = repeat_with(|| challenger.sample_algebra_element::<Challenge>())
                .take(concat_mats_meta.max_log_width())
                .collect_vec();
            let eq_rs = concat_mats_meta.eq_r_per_matrix::<Challenge>(&r);
            let mut statement = LinearEqStatement::initialize(num_variables);
            round.iter().enumerate().for_each(|(idx, evals)| {
                evals.iter().for_each(|(query, evals)| {
                    let (constraint, sum) =
                        concat_mats_meta.constraint_with_eq_r(idx, query, evals, &r, &eq_rs[idx]);
                    match constraint {
                        ConcatConstraint::Point(point) => {
                            statement.add_evaluated_constraint(point, sum);
                        }
                        ConcatConstraint::TensorProduct {
                            range_start,
                            log_range_len,
                            row_weights,
                            col_weights,
                        } => {
                            statement.add_tensor_product_constraint(
                                range_start,
                                log_range_len,
                                row_weights,
                                col_weights,
                                sum,
                            );
                        }
                    }
                })
            });
            let statement = statement.into_eq_statement();

            Verifier::new(&config)
                .verify::<<Val as Field>::Packing, Val, <Val as Field>::Packing, DIGEST_ELEMS>(
                    proof,
                    challenger,
                    &parsed_commitment,
                    statement,
                )
                .map(|_| ())
        })
    }
}

impl<Val, Dft, Hash, Compression, Challenge, Challenger> MlPcs<Challenge, Challenger>
    for WhirPcs<Val, Dft, Hash, Compression, 4, KeccakFlavor>
where
    Val: TwoAdicField + PrimeField64 + Ord + Serialize + DeserializeOwned,
    Dft: TwoAdicSubgroupDft<Val>,
    Hash: Clone + Sync + CryptographicHasher<Val, [u64; 4]> + CryptographicHasher<Val, [u64; 4]>,
    Compression: Clone + Sync + PseudoCompressionFunction<[u64; 4], 2>,
    Challenge: TwoAdicField + ExtensionField<Val> + Serialize + DeserializeOwned,
    Challenger:
        FieldChallenger<Val> + GrindingChallenger<Witness = Val> + CanObserve<SymHash<Val, u64, 4>>,
    [u64; 4]: Serialize + DeserializeOwned,
{
    type Val = Val;
    type Commitment = <WhirMmcsKeccak<Val, Hash, Compression> as Mmcs<Val>>::Commitment;
    type ProverData = (
        ConcatMats<Val>,
        RefCell<
            Option<
                <WhirMmcsKeccak<Val, Hash, Compression> as Mmcs<Val>>::ProverData<DenseMatrix<Val>>,
            >,
        >,
    );
    type Evaluations<'a> = HorizontallyTruncated<Val, RowMajorMatrixView<'a, Val>>;
    type Proof = Vec<WhirProof<Val, Challenge, u64, 4>>;
    type Error = VerifierError;

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
                1 << (num_variables + config.starting_log_inv_rate
                    - config.folding_factor.at_round(0)),
                Val::ZERO,
            );
            self.dft.dft_batch(mat).to_row_major_matrix()
        });

        let mmcs = WhirMmcsKeccak::<Val, Hash, Compression>::new(
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
                domainsep.commit_statement::<_, _, _, 4>(&config);
                domainsep.add_whir_proof::<_, _, _, 4>(&config);
                domainsep.observe_domain_separator(challenger);

                let mut proof = WhirProof::<Val, Challenge, u64, 4>::from_protocol_parameters(
                    &self.whir,
                    num_variables,
                );

                let polynomial = EvaluationsList::new(concat_mats.values.clone());

                let root = merkle_tree.borrow().as_ref().unwrap().root();
                proof.initial_commitment = *root.as_ref();
                challenger.observe(root);

                let mut ood_statement = LinearEqStatement::initialize(num_variables);
                (0..config.commitment_ood_samples).for_each(|_| {
                    let u: Challenge = challenger.sample_algebra_element();
                    let point = MultilinearPoint::expand_from_univariate(u, num_variables);
                    let eval = polynomial.evaluate_hypercube_base::<Challenge>(&point);
                    proof.initial_ood_answers.push(eval);
                    challenger.observe_algebra_element(eval);
                    ood_statement.add_evaluated_constraint(point, eval);
                });

                let r = repeat_with(|| challenger.sample_algebra_element::<Challenge>())
                    .take(concat_mats.meta.max_log_width())
                    .collect_vec();

                let eq_rs = concat_mats.meta.eq_r_per_matrix::<Challenge>(&r);
                let statement = info_span!("build EqStatement").in_scope(|| {
                    let mut statement = LinearEqStatement::initialize(num_variables);
                    queries_and_evals
                        .iter()
                        .enumerate()
                        .for_each(|(idx, queries_and_evals)| {
                            queries_and_evals.iter().for_each(|(query, evals)| {
                                let (constraint, sum) = concat_mats.meta.constraint_with_eq_r(
                                    idx,
                                    query,
                                    evals,
                                    &r,
                                    &eq_rs[idx],
                                );
                                match constraint {
                                    ConcatConstraint::Point(point) => {
                                        statement.add_evaluated_constraint(point, sum);
                                    }
                                    ConcatConstraint::TensorProduct {
                                        range_start,
                                        log_range_len,
                                        row_weights,
                                        col_weights,
                                    } => {
                                        statement.add_tensor_product_constraint(
                                            range_start,
                                            log_range_len,
                                            row_weights,
                                            col_weights,
                                            sum,
                                        );
                                    }
                                }
                            })
                        });
                    statement
                });

                if statement.has_linear_constraints() {
                    match proof.initial_phase {
                        InitialPhase::WithStatementSkip(_)
                        | InitialPhase::WithStatementSvo { .. } => {
                            proof.initial_phase = InitialPhase::WithStatement {
                                sumcheck: SumcheckData::default(),
                            };
                        }
                        InitialPhase::WithStatement { .. }
                        | InitialPhase::WithoutStatement { .. } => {}
                    }
                }

                let witness = Witness::<Challenge, Val, DenseMatrix<Val>, u64, 4> {
                    polynomial,
                    prover_data: Arc::new(merkle_tree.take().unwrap()),
                    ood_statement: ood_statement.into_eq_statement(),
                };

                info_span!("whir_p3::prove").in_scope(|| {
                    let statement = statement.into_eq_statement();
                    Prover(&config)
                        .prove::<_, Val, u64, u64, 4>(
                            &self.dft, &mut proof, challenger, statement, witness,
                        )
                        .expect("WHIR proving failed");
                });

                proof
            })
            .collect()
    }

    fn verify(
        &self,
        rounds: Vec<(
            Self::Commitment,
            Vec<Vec<(MlQuery<Challenge>, Vec<Challenge>)>>,
        )>,
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
            domainsep.commit_statement::<_, _, _, 4>(&config);
            domainsep.add_whir_proof::<_, _, _, 4>(&config);
            domainsep.observe_domain_separator(challenger);

            let parsed_commitment =
                CommitmentReader::new(&config).parse_commitment::<u64, 4>(proof, challenger);
            debug_assert_eq!(parsed_commitment.root, commitment);

            let r = repeat_with(|| challenger.sample_algebra_element::<Challenge>())
                .take(concat_mats_meta.max_log_width())
                .collect_vec();
            let eq_rs = concat_mats_meta.eq_r_per_matrix::<Challenge>(&r);
            let mut statement = LinearEqStatement::initialize(num_variables);
            round.iter().enumerate().for_each(|(idx, evals)| {
                evals.iter().for_each(|(query, ys)| {
                    let (constraint, sum) =
                        concat_mats_meta.constraint_with_eq_r(idx, query, ys, &r, &eq_rs[idx]);
                    match constraint {
                        ConcatConstraint::Point(point) => {
                            statement.add_evaluated_constraint(point, sum);
                        }

                        ConcatConstraint::TensorProduct {
                            range_start,
                            log_range_len,
                            row_weights,
                            col_weights,
                        } => {
                            statement.add_tensor_product_constraint(
                                range_start,
                                log_range_len,
                                row_weights,
                                col_weights,
                                sum,
                            );
                        }
                    }
                })
            });
            let statement = statement.into_eq_statement();

            Verifier::new(&config)
                .verify::<Val, u64, u64, 4>(proof, challenger, &parsed_commitment, statement)
                .map(|_| ())
        })
    }
}

pub struct ConcatMatsMeta {
    pub(crate) log_b: usize,
    dimensions: Vec<Dimensions>,
    ranges: Vec<Range<usize>>,
}

pub(crate) enum ConcatConstraint<F> {
    Point(MultilinearPoint<F>),
    TensorProduct {
        range_start: usize,
        log_range_len: usize,
        row_weights: EvaluationsList<F>,
        col_weights: EvaluationsList<F>,
    },
}

impl ConcatMatsMeta {
    pub(crate) fn new(dims: Vec<Dimensions>) -> Self {
        let (dimensions, ranges) = dims
            .iter()
            .enumerate()
            // Sorted by matrix size in descending order.
            .sorted_by_key(|(_, dim)| Reverse(dim.width * dim.height))
            // Calculate sub-cube range for each matrix (power-of-2 aligned).
            .scan(0, |offset, (idx, dim)| {
                let size = dim.width.next_power_of_two() * dim.height;
                let offset = replace(offset, *offset + size);
                Some((idx, dim, offset..offset + size))
            })
            // Store the dimension and range in original order.
            .sorted_by_key(|(idx, _, _)| *idx)
            .map(|(_, dim, range)| (dim, range))
            .collect::<(Vec<_>, Vec<_>)>();
        // Calculate number of variable of concated polynomial.
        let log_b = log2_ceil_usize(
            ranges
                .iter()
                .map(|range| range.end)
                .max()
                .unwrap_or_default(),
        );
        Self {
            log_b,
            dimensions,
            ranges,
        }
    }

    pub(crate) fn max_log_width(&self) -> usize {
        self.dimensions
            .iter()
            .map(|dim| log2_ceil_usize(dim.width))
            .max()
            .unwrap_or_default()
    }

    pub(crate) fn eq_r_per_matrix<Challenge: Field>(&self, r: &[Challenge]) -> Vec<Vec<Challenge>> {
        self.dimensions
            .iter()
            .map(|dim| {
                let log_width = log2_ceil_usize(dim.width);
                eq_poly(&r[..log_width], Challenge::ONE)
            })
            .collect()
    }

    pub(crate) fn constraint_with_eq_r<Challenge: Field>(
        &self,
        idx: usize,
        query: &MlQuery<Challenge>,
        ys: &[Challenge],
        r: &[Challenge],
        eq_r: &[Challenge],
    ) -> (ConcatConstraint<Challenge>, Challenge) {
        let log_width = log2_ceil_usize(self.dimensions[idx].width);

        let r = &r[..log_width];

        debug_assert_eq!(eq_r.len(), 1 << log_width);

        let sum = dot_product(cloned(ys), cloned(&eq_r[..ys.len()]));

        match query {
            MlQuery::Eq(z) => {
                let point = rev(chain![
                    cloned(r),
                    cloned(z),
                    (log2_strict_usize(self.ranges[idx].len())..self.log_b)
                        .map(|i| Challenge::from_bool((self.ranges[idx].start >> i) & 1 == 1))
                ])
                .collect();
                (ConcatConstraint::Point(MultilinearPoint::new(point)), sum)
            }
            MlQuery::EqRotateRight(_, _) => {
                // `EqRotateRight` represents a linear functional on the committed evaluations.
                // We encode it as a tensor-product constraint over the matrix's range.
                let row_weights = EvaluationsList::new(query.to_mle(Challenge::ONE));
                let col_weights = EvaluationsList::new(eq_r.to_vec());
                let log_range_len = log2_strict_usize(self.ranges[idx].len());

                (
                    ConcatConstraint::TensorProduct {
                        range_start: self.ranges[idx].start,
                        log_range_len,
                        row_weights,
                        col_weights,
                    },
                    sum,
                )
            }
        }
    }
}

pub struct ConcatMats<Val> {
    pub(crate) values: Vec<Val>,
    pub(crate) meta: ConcatMatsMeta,
}

impl<Val: Field> ConcatMats<Val> {
    pub(crate) fn new(mats: Vec<RowMajorMatrix<Val>>) -> Self {
        let meta = ConcatMatsMeta::new(mats.iter().map(Matrix::dimensions).collect());
        let mut values = Val::zero_vec(1 << meta.log_b);
        izip!(&meta.ranges, mats).for_each(|(range, mat)| {
            // Copy and pad each row into power-of-2 length into concated polynomial.
            values[range.clone()]
                .par_chunks_mut(mat.width().next_power_of_two())
                .zip(mat.par_row_slices())
                .for_each(|(dst, src)| dst[..src.len()].copy_from_slice(src));
        });
        Self { values, meta }
    }

    pub(crate) fn mat(
        &self,
        idx: usize,
    ) -> HorizontallyTruncated<Val, RowMajorMatrixView<'_, Val>> {
        HorizontallyTruncated::new(
            RowMajorMatrixView::new(
                &self.values[self.meta.ranges[idx].clone()],
                self.meta.dimensions[idx].width.next_power_of_two(),
            ),
            self.meta.dimensions[idx].width,
        )
        .unwrap()
    }
}
