use core::iter::repeat_with;

use itertools::{Itertools, izip};
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_ml_pcs::{MlPcs, MlQuery};
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn seeded_rng() -> impl Rng {
    StdRng::seed_from_u64(0)
}

fn do_test_whir_pcs<Val, Challenge, Challenger, P>(
    (pcs, challenger): &(P, Challenger),
    log_bs_by_round: &[&[usize]],
) where
    P: MlPcs<Challenge, Challenger, Val = Val>,
    Val: Field,
    StandardUniform: Distribution<Val>,
    Challenge: ExtensionField<Val>,
    Challenger: Clone
        + CanObserve<P::Commitment>
        + FieldChallenger<Val>
        + GrindingChallenger<Witness = Val>,
{
    let num_rounds = log_bs_by_round.len();
    let mut rng = seeded_rng();

    let mut p_challenger = challenger.clone();

    let log_bs_and_polys_by_round = log_bs_by_round
        .iter()
        .map(|log_bs| {
            log_bs
                .iter()
                .map(|&log_b| {
                    let height = 1 << log_b;
                    // random width 5-15
                    let width = 5 + rng.random_range(0..=10);
                    (log_b, RowMajorMatrix::<Val>::rand(&mut rng, height, width))
                })
                .collect_vec()
        })
        .collect_vec();

    let (commits_by_round, data_by_round): (Vec<_>, Vec<_>) = log_bs_and_polys_by_round
        .iter()
        .map(|log_bs_and_polys| {
            pcs.commit(
                log_bs_and_polys
                    .iter()
                    .map(|(_, poly)| poly.clone())
                    .collect(),
            )
        })
        .unzip();
    assert_eq!(commits_by_round.len(), num_rounds);
    assert_eq!(data_by_round.len(), num_rounds);
    p_challenger.observe_slice(&commits_by_round);

    let zeta: Vec<Challenge> = repeat_with(|| p_challenger.sample_algebra_element())
        .take(itertools::max(log_bs_by_round.iter().copied().flatten().copied()).unwrap())
        .collect_vec();

    let queries_by_round = log_bs_by_round
        .iter()
        .map(|log_bs| {
            log_bs
                .iter()
                .map(|log_b| vec![MlQuery::Eq(zeta[..*log_b].to_vec())])
                .collect_vec()
        })
        .collect_vec();
    let opening_by_round = data_by_round
        .iter()
        .zip(&queries_by_round)
        .map(|(data, queries)| {
            queries
                .iter()
                .enumerate()
                .map(|(idx, queries)| {
                    let mat = pcs.get_evaluations(data, idx);
                    queries
                        .iter()
                        .map(|query| mat.columnwise_dot_product(&query.to_mle(Challenge::ONE)))
                        .collect_vec()
                })
                .collect_vec()
        })
        .collect_vec();

    let data_and_queries_and_evals = data_by_round
        .iter()
        .zip(
            queries_by_round
                .iter()
                .zip(&opening_by_round)
                .map(|(queries, evals)| {
                    queries
                        .iter()
                        .zip(evals)
                        .map(|(queries, evals)| {
                            queries
                                .iter()
                                .zip(evals)
                                .map(|(query, evals)| (query.clone(), evals.to_vec()))
                                .collect_vec()
                        })
                        .collect_vec()
                })
                .collect_vec(),
        )
        .collect_vec();
    let proof = pcs.open(data_and_queries_and_evals, &mut p_challenger);

    // Verify the proof.
    let mut v_challenger = challenger.clone();
    v_challenger.observe_slice(&commits_by_round);
    let verifier_zeta: Vec<Challenge> = repeat_with(|| v_challenger.sample_algebra_element())
        .take(itertools::max(log_bs_by_round.iter().copied().flatten().copied()).unwrap())
        .collect_vec();
    assert_eq!(verifier_zeta, zeta);

    let commits_and_claims_by_round = izip!(
        commits_by_round,
        log_bs_and_polys_by_round,
        opening_by_round
    )
    .map(|(commit, log_bs_and_polys, openings)| {
        let claims = log_bs_and_polys
            .iter()
            .zip(openings)
            .map(|((log_b, _), mat_openings)| {
                vec![(
                    MlQuery::Eq(zeta[..*log_b].to_vec()),
                    mat_openings[0].clone(),
                )]
            })
            .collect_vec();
        (commit, claims)
    })
    .collect_vec();
    assert_eq!(commits_and_claims_by_round.len(), num_rounds);

    pcs.verify(commits_and_claims_by_round, &proof, &mut v_challenger)
        .unwrap()
}

// Set it up so we create tests inside a module for each pcs, so we get nice error reports
// specific to a failing PCS.
macro_rules! make_tests_for_pcs {
    ($p:expr) => {
        #[test]
        fn single() {
            let p = $p;
            for i in 3..6 {
                $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[i]]);
            }
        }

        #[test]
        fn many_equal() {
            let p = $p;
            for i in 5..8 {
                $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[i; 5]]);
            }
        }

        #[test]
        fn many_different() {
            let p = $p;
            for i in 3..8 {
                let log_bs = (3..3 + i).collect::<Vec<_>>();
                $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&log_bs]);
            }
        }

        #[test]
        fn many_different_rev() {
            let p = $p;
            for i in 3..8 {
                let log_bs = (3..3 + i).rev().collect::<Vec<_>>();
                $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&log_bs]);
            }
        }

        #[test]
        fn multiple_rounds() {
            let p = $p;
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[3]]);
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[3], &[3]]);
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[3], &[2]]);
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[2], &[3]]);
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[3, 4], &[3, 4]]);
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[4, 2], &[4, 2]]);
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[2, 2], &[3, 3]]);
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[3, 3], &[2, 2]]);
            $crate::do_test_whir_pcs::<_, super::Challenge, _, _>(&p, &[&[2], &[3, 3]]);
        }
    };
}

mod koala_bear_whir_pcs {
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::Poseidon2KoalaBear;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirPcs};
    use whir_p3::whir::parameters::InitialPhaseConfig;
    use whir_p3::whir::proof::WhirProof;

    use super::*;

    type Val = KoalaBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type Perm = Poseidon2KoalaBear<16>;
    const DIGEST_ELEMS: usize = 8;
    type FieldHash = PaddingFreeSponge<Perm, 16, 8, DIGEST_ELEMS>;
    type Compress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, 16>;
    type Dft = Radix2DitParallel<Val>;
    type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
    type MyPcs = WhirPcs<Val, Dft, FieldHash, Compress, DIGEST_ELEMS>;
    type Commitment = <MyPcs as MlPcs<Challenge, Challenger>>::Commitment;
    type Proof = Vec<WhirProof<Val, Challenge, Val, DIGEST_ELEMS>>;

    fn get_pcs(
        log_blowup: usize,
        folding_factor: usize,
        first_round_folding_factor: usize,
    ) -> (MyPcs, Challenger) {
        let dft = Dft::default();
        let security_level = 100;
        let pow_bits = 20;
        let mut rng = seeded_rng();
        let perm = Perm::new_from_rng_128(&mut rng);
        let field_hash = FieldHash::new(perm.clone());
        let compress = Compress::new(perm.clone());
        let whir_params = ProtocolParameters {
            initial_phase_config: InitialPhaseConfig::WithStatementClassic,
            security_level,
            pow_bits,
            rs_domain_initial_reduction_factor: 3,
            folding_factor: FoldingFactor::ConstantFromSecondRound(
                first_round_folding_factor,
                folding_factor,
            ),
            merkle_hash: field_hash,
            merkle_compress: compress,
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: log_blowup,
        };
        (MyPcs::new(dft, whir_params), Challenger::new(perm))
    }

    fn build_single_round(
        (pcs, challenger): &(MyPcs, Challenger),
        log_b: usize,
    ) -> (
        Vec<(Commitment, Vec<Vec<(MlQuery<Challenge>, Vec<Challenge>)>>)>,
        Proof,
    ) {
        let mut rng = seeded_rng();
        let mut p_challenger = challenger.clone();

        let height = 1 << log_b;
        let width = 8;
        let poly = RowMajorMatrix::<Val>::rand(&mut rng, height, width);
        let (commitment, prover_data) =
            <MyPcs as MlPcs<Challenge, Challenger>>::commit(pcs, vec![poly.clone()]);
        p_challenger.observe(commitment.clone());

        let zeta: Vec<Challenge> = repeat_with(|| p_challenger.sample_algebra_element())
            .take(log_b)
            .collect();
        let queries = vec![vec![MlQuery::Eq(zeta.clone())]];
        let opening = {
            let mat =
                <MyPcs as MlPcs<Challenge, Challenger>>::get_evaluations(pcs, &prover_data, 0);
            vec![vec![mat.columnwise_dot_product(
                &queries[0][0].to_mle(Challenge::ONE),
            )]]
        };

        let data_and_queries_and_evals = vec![(
            &prover_data,
            vec![vec![(queries[0][0].clone(), opening[0][0].to_vec())]],
        )];
        let proof = <MyPcs as MlPcs<Challenge, Challenger>>::open(
            pcs,
            data_and_queries_and_evals,
            &mut p_challenger,
        );

        let commits_and_claims = vec![(
            commitment,
            vec![vec![(MlQuery::Eq(zeta), opening[0][0].clone())]],
        )];

        (commits_and_claims, proof)
    }

    fn build_single_round_rotate(
        (pcs, challenger): &(MyPcs, Challenger),
        log_b: usize,
        rotate_by: usize,
    ) -> (
        Vec<(Commitment, Vec<Vec<(MlQuery<Challenge>, Vec<Challenge>)>>)>,
        Proof,
    ) {
        let mut rng = seeded_rng();
        let mut p_challenger = challenger.clone();

        let height = 1 << log_b;
        let width = 8;
        let poly = RowMajorMatrix::<Val>::rand(&mut rng, height, width);
        let (commitment, prover_data) =
            <MyPcs as MlPcs<Challenge, Challenger>>::commit(pcs, vec![poly.clone()]);
        p_challenger.observe(commitment.clone());

        let zeta: Vec<Challenge> = repeat_with(|| p_challenger.sample_algebra_element())
            .take(log_b)
            .collect();
        let queries = vec![vec![MlQuery::EqRotateRight(zeta.clone(), rotate_by)]];
        let opening = {
            let mat =
                <MyPcs as MlPcs<Challenge, Challenger>>::get_evaluations(pcs, &prover_data, 0);
            vec![vec![mat.columnwise_dot_product(
                &queries[0][0].to_mle(Challenge::ONE),
            )]]
        };

        let data_and_queries_and_evals = vec![(
            &prover_data,
            vec![vec![(queries[0][0].clone(), opening[0][0].to_vec())]],
        )];
        let proof = <MyPcs as MlPcs<Challenge, Challenger>>::open(
            pcs,
            data_and_queries_and_evals,
            &mut p_challenger,
        );

        let commits_and_claims = vec![(
            commitment,
            vec![vec![(
                MlQuery::EqRotateRight(zeta, rotate_by),
                opening[0][0].clone(),
            )]],
        )];

        (commits_and_claims, proof)
    }

    mod blowup_1 {
        make_tests_for_pcs!(super::get_pcs(1, 4, 4));
    }

    #[test]
    fn negative_tampered_proof_rejected() {
        let p = get_pcs(1, 4, 4);
        let (commits_and_claims, proof) = build_single_round(&p, 4);

        let commits = commits_and_claims
            .iter()
            .map(|(c, _)| c.clone())
            .collect_vec();
        let mut v_challenger = p.1.clone();
        v_challenger.observe_slice(&commits);
        if let MlQuery::Eq(z) = &commits_and_claims[0].1[0][0].0 {
            let verifier_zeta: Vec<Challenge> =
                repeat_with(|| v_challenger.sample_algebra_element())
                    .take(z.len())
                    .collect();
            assert_eq!(&verifier_zeta, z);
        }
        <MyPcs as MlPcs<Challenge, Challenger>>::verify(
            &p.0,
            commits_and_claims.clone(),
            &proof,
            &mut v_challenger,
        )
        .unwrap();

        let mut bad_proof = proof.clone();
        if let Some(first) = bad_proof.first_mut() {
            if let Some(val) = first.initial_ood_answers.first_mut() {
                *val += Challenge::ONE;
            } else if let Some(round) = first.rounds.first_mut() {
                if let Some(val) = round.ood_answers.first_mut() {
                    *val += Challenge::ONE;
                } else {
                    round.pow_witness += Val::ONE;
                }
            } else {
                first.final_pow_witness += Val::ONE;
            }
        }

        let mut bad_challenger = p.1.clone();
        bad_challenger.observe_slice(&commits);
        if let MlQuery::Eq(z) = &commits_and_claims[0].1[0][0].0 {
            let verifier_zeta: Vec<Challenge> =
                repeat_with(|| bad_challenger.sample_algebra_element())
                    .take(z.len())
                    .collect();
            assert_eq!(&verifier_zeta, z);
        }
        assert!(
            <MyPcs as MlPcs<Challenge, Challenger>>::verify(
                &p.0,
                commits_and_claims,
                &bad_proof,
                &mut bad_challenger,
            )
            .is_err()
        );
    }

    #[test]
    fn negative_tampered_claim_rejected() {
        let p = get_pcs(1, 4, 4);
        let (mut commits_and_claims, proof) = build_single_round(&p, 4);

        let (_, claims) = &mut commits_and_claims[0];
        claims[0][0].1[0] += Challenge::ONE;

        let commits = commits_and_claims
            .iter()
            .map(|(c, _)| c.clone())
            .collect_vec();
        let mut v_challenger = p.1.clone();
        v_challenger.observe_slice(&commits);
        if let MlQuery::Eq(z) = &commits_and_claims[0].1[0][0].0 {
            let verifier_zeta: Vec<Challenge> =
                repeat_with(|| v_challenger.sample_algebra_element())
                    .take(z.len())
                    .collect();
            assert_eq!(&verifier_zeta, z);
        }
        assert!(
            <MyPcs as MlPcs<Challenge, Challenger>>::verify(
                &p.0,
                commits_and_claims,
                &proof,
                &mut v_challenger,
            )
            .is_err()
        );
    }

    #[test]
    fn negative_tampered_proof_rejected_eq_rotate_right() {
        let p = get_pcs(1, 4, 4);
        let (commits_and_claims, proof) = build_single_round_rotate(&p, 4, 1);

        let commits = commits_and_claims
            .iter()
            .map(|(c, _)| c.clone())
            .collect_vec();
        let mut v_challenger = p.1.clone();
        v_challenger.observe_slice(&commits);
        if let MlQuery::EqRotateRight(z, _) = &commits_and_claims[0].1[0][0].0 {
            let verifier_zeta: Vec<Challenge> =
                repeat_with(|| v_challenger.sample_algebra_element())
                    .take(z.len())
                    .collect();
            assert_eq!(&verifier_zeta, z);
        }
        <MyPcs as MlPcs<Challenge, Challenger>>::verify(
            &p.0,
            commits_and_claims.clone(),
            &proof,
            &mut v_challenger,
        )
        .unwrap();

        let mut bad_proof = proof.clone();
        if let Some(first) = bad_proof.first_mut() {
            if let Some(val) = first.initial_ood_answers.first_mut() {
                *val += Challenge::ONE;
            } else if let Some(round) = first.rounds.first_mut() {
                if let Some(val) = round.ood_answers.first_mut() {
                    *val += Challenge::ONE;
                } else {
                    round.pow_witness += Val::ONE;
                }
            } else {
                first.final_pow_witness += Val::ONE;
            }
        }

        let mut bad_challenger = p.1.clone();
        bad_challenger.observe_slice(&commits);
        if let MlQuery::EqRotateRight(z, _) = &commits_and_claims[0].1[0][0].0 {
            let verifier_zeta: Vec<Challenge> =
                repeat_with(|| bad_challenger.sample_algebra_element())
                    .take(z.len())
                    .collect();
            assert_eq!(&verifier_zeta, z);
        }
        assert!(
            <MyPcs as MlPcs<Challenge, Challenger>>::verify(
                &p.0,
                commits_and_claims,
                &bad_proof,
                &mut bad_challenger,
            )
            .is_err()
        );
    }

    #[test]
    fn negative_tampered_claim_rejected_eq_rotate_right() {
        let p = get_pcs(1, 4, 4);
        let (mut commits_and_claims, proof) = build_single_round_rotate(&p, 4, 1);

        let (_, claims) = &mut commits_and_claims[0];
        claims[0][0].1[0] += Challenge::ONE;

        let commits = commits_and_claims
            .iter()
            .map(|(c, _)| c.clone())
            .collect_vec();
        let mut v_challenger = p.1.clone();
        v_challenger.observe_slice(&commits);
        if let MlQuery::EqRotateRight(z, _) = &commits_and_claims[0].1[0][0].0 {
            let verifier_zeta: Vec<Challenge> =
                repeat_with(|| v_challenger.sample_algebra_element())
                    .take(z.len())
                    .collect();
            assert_eq!(&verifier_zeta, z);
        }
        assert!(
            <MyPcs as MlPcs<Challenge, Challenger>>::verify(
                &p.0,
                commits_and_claims,
                &proof,
                &mut v_challenger,
            )
            .is_err()
        );
    }

    mod blowup_2 {
        make_tests_for_pcs!(super::get_pcs(2, 4, 4));
    }
}
