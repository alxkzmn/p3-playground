use p3_air::{Air, AirBuilder, BaseAir, BaseAirWithPublicValues};
use p3_hyperplonk::keygen_vk;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type Val = KoalaBear;

#[derive(Clone, Copy)]
struct TransitionGatedAir;

impl<F> BaseAir<F> for TransitionGatedAir {
    fn width(&self) -> usize {
        1
    }
}

impl<F> BaseAirWithPublicValues<F> for TransitionGatedAir {
    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder> Air<AB> for TransitionGatedAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        builder
            .when_transition()
            .assert_eq(local[0].clone(), next[0].clone());
    }
}

#[derive(Clone, Copy)]
struct UngatedAir;

impl<F> BaseAir<F> for UngatedAir {
    fn width(&self) -> usize {
        1
    }
}

impl<F> BaseAirWithPublicValues<F> for UngatedAir {
    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder> Air<AB> for UngatedAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        builder.assert_eq(local[0].clone(), next[0].clone());
    }
}

#[test]
fn transition_gate_increases_multilinear_degree_metadata() {
    let air = TransitionGatedAir;
    let vk = keygen_vk::<Val, _>([&air]);
    let meta = &vk.metas()[0];

    assert!(
        meta.zero_check_mv_degree > meta.zero_check_uv_degree,
        "expected MV degree ({}) to be greater than UV degree ({}) for transition-gated constraints",
        meta.zero_check_mv_degree,
        meta.zero_check_uv_degree
    );
}

#[test]
fn ungated_constraint_keeps_same_degree_metadata() {
    let air = UngatedAir;
    let vk = keygen_vk::<Val, _>([&air]);
    let meta = &vk.metas()[0];

    assert_eq!(
        meta.zero_check_mv_degree, meta.zero_check_uv_degree,
        "ungated constraints should have identical UV and MV degree metadata"
    );
}
