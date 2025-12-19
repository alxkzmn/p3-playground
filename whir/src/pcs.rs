use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::Reverse;
use core::iter::repeat_with;
use core::marker::PhantomData;
use core::mem::replace;
use core::ops::Range;

use itertools::{Itertools, chain, cloned, izip, rev};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PrimeField64, TwoAdicField, dot_product};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::horizontally_truncated::HorizontallyTruncated;
use p3_matrix::{Dimensions, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_ml_pcs::{MlPcs, MlQuery, eq_poly};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_util::{log2_ceil_usize, log2_strict_usize};
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
use whir_p3::whir::proof::WhirProof;
use whir_p3::whir::prover::Prover;
use whir_p3::whir::verifier::Verifier;

type WhirMmcs<Val, Hash, Compression, const DIGEST_ELEMS: usize> = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compression,
    DIGEST_ELEMS,
>;

#[derive(Debug)]
pub struct WhirPcs<Val, Dft, Hash, Compression, const DIGEST_ELEMS: usize> {
    dft: Dft,
    whir: whir_p3::parameters::ProtocolParameters<Hash, Compression>,
    _phantom: PhantomData<Val>,
}

impl<Val, Dft, Hash, Compression, const DIGEST_ELEMS: usize>
    WhirPcs<Val, Dft, Hash, Compression, DIGEST_ELEMS>
{
    pub const fn new(
        dft: Dft,
        whir: whir_p3::parameters::ProtocolParameters<Hash, Compression>,
    ) -> Self {
        Self {
            dft,
            whir,
            _phantom: PhantomData,
        }
    }
}

impl<Val, Dft, Hash, Compression, Challenge, Challenger, const DIGEST_ELEMS: usize>
    MlPcs<Challenge, Challenger> for WhirPcs<Val, Dft, Hash, Compression, DIGEST_ELEMS>
where
    Val: TwoAdicField + PrimeField64 + Ord + Serialize + DeserializeOwned,
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
    Challenger: FieldChallenger<Val> + GrindingChallenger<Witness = Val>,
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
    type Proof = Vec<WhirProof<Val, Challenge, DIGEST_ELEMS>>;
    type Error = WhirError;

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
                let mut proof = WhirProof::<Val, Challenge, DIGEST_ELEMS>::from_protocol_parameters(
                    &self.whir,
                    num_variables,
                );

                let polynomial = EvaluationsList::new(concat_mats.values.clone());

                // Fill the initial commitment root and observe it (matches verifier parsing logic).
                let root = merkle_tree.borrow().as_ref().unwrap().root();
                proof.initial_commitment = *root.as_ref();
                challenger.observe_slice(proof.initial_commitment.as_ref());

                // Commitment OOD statements (points are sampled from the challenger, then answers observed).
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

                let witness = Witness {
                    polynomial,
                    prover_data: Arc::new(merkle_tree.take().unwrap()),
                    ood_statement,
                };

                info_span!("whir_p3::prove").in_scope(|| {
                    Prover(&config)
                        .prove(&self.dft, &mut proof, challenger, statement, witness)
                        .expect("WHIR proving failed");
                });

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
            let parsed_commitment =
                CommitmentReader::new(&config).parse_commitment(proof, challenger);
            debug_assert_eq!(parsed_commitment.root, commitment);

            // Sample the same column-combination randomness and rebuild the same statement.
            let r = repeat_with(|| challenger.sample_algebra_element::<Challenge>())
                .take(concat_mats_meta.max_log_width())
                .collect_vec();
            let mut statement = EqStatement::initialize(num_variables);
            round.iter().enumerate().for_each(|(idx, evals)| {
                evals.iter().for_each(|(query, evals)| {
                    let (point, sum) = concat_mats_meta.constraint(idx, query, evals, &r);
                    statement.add_evaluated_constraint(point, sum);
                })
            });

            Verifier::new(&config)
                .verify::<DIGEST_ELEMS>(proof, challenger, &parsed_commitment, statement)
                .map(|_| ())
                .map_err(Into::into)
        })
    }
}

pub struct ConcatMatsMeta {
    log_b: usize,
    dimensions: Vec<Dimensions>,
    ranges: Vec<Range<usize>>,
}

impl ConcatMatsMeta {
    fn new(dims: Vec<Dimensions>) -> Self {
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

    fn max_log_width(&self) -> usize {
        self.dimensions
            .iter()
            .map(|dim| log2_ceil_usize(dim.width))
            .max()
            .unwrap_or_default()
    }

    fn constraint<Challenge: Field>(
        &self,
        idx: usize,
        query: &MlQuery<Challenge>,
        ys: &[Challenge],
        r: &[Challenge],
    ) -> (MultilinearPoint<Challenge>, Challenge) {
        let log_width = log2_ceil_usize(self.dimensions[idx].width);

        let r = &r[..log_width];
        let eq_r = eq_poly(r, Challenge::ONE);

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
                (MultilinearPoint::new(point), sum)
            }
            // `EqRotateRight` represents a linear functional on the committed evaluations.
            // WHIR currently only supports point-evaluation statements, so this PCS backend
            // does not support it.
            MlQuery::EqRotateRight(_, _) => {
                unimplemented!("WhirPcs does not support MlQuery::EqRotateRight")
            }
            // MlQuery::EqRotateRight(_, _) => {
            //     let mut weight = Challenge::zero_vec(1 << self.log_b);
            //     weight[self.ranges[idx].clone()]
            //         .par_chunks_mut(eq_r.len())
            //         .zip(query.to_mle(Challenge::ONE))
            //         .for_each(|(weight, query)| {
            //             izip!(weight, &eq_r).for_each(|(weight, eq_r)| *weight = *eq_r * query)
            //         });
            //     Weights::linear(EvaluationsList::new(weight))
            // }
        }
    }
}

pub struct ConcatMats<Val> {
    values: Vec<Val>,
    meta: ConcatMatsMeta,
}

impl<Val: Field> ConcatMats<Val> {
    fn new(mats: Vec<RowMajorMatrix<Val>>) -> Self {
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

    fn mat(&self, idx: usize) -> HorizontallyTruncated<Val, RowMajorMatrixView<'_, Val>> {
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
