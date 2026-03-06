use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use p3_air::{Air, AirBuilder, BaseAir, BaseAirWithPublicValues};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_hyperplonk::{HyperPlonkConfig, ProverInput, VerifierInput, keygen, prove, verify};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_poseidon2_air::{RoundConstants, generate_trace_rows, num_cols};
use p3_whir::{
    FoldingFactor, KeccakNodeCompress, KeccakU32BeLeafHasher, ProtocolParameters,
    SecurityAssumption, WhirPcs,
};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

#[cfg(target_family = "unix")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

type Val = KoalaBear;
type Challenge = BinomialExtensionField<Val, 4>;
type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;
type FieldHash = KeccakU32BeLeafHasher;
type Compress = KeccakNodeCompress;
type Dft<Val> = Radix2DitParallel<Val>;
type Pcs<Val, Dft> = WhirPcs<Val, Dft, FieldHash, Compress, 4>;
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

impl<F> BaseAir<F> for Poseidon2Air {
    fn width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }
}

impl<F> BaseAirWithPublicValues<F> for Poseidon2Air {}

impl<AB: AirBuilder<F = Val>> Air<AB> for Poseidon2Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
    }
}

impl<F> BaseAir<F> for &Poseidon2Air {
    fn width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }
}

impl<F> BaseAirWithPublicValues<F> for &Poseidon2Air {}

impl<AB: AirBuilder<F = Val>> Air<AB> for &Poseidon2Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
    }
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("hyperplonk/koala_bear_poseidon2");
    group.sample_size(10);

    let mut rng = StdRng::from_seed([1u8; 32]);
    let round_constants = RoundConstants::from_rng(&mut rng);
    let air = Poseidon2Air(p3_poseidon2_air::Poseidon2Air::new(round_constants.clone()));
    let (vk, pk) = keygen([&air]);

    let dft = Dft::default();
    // FIXME: Set to 128 when higher degree extension field is available.
    let security_level = 100;
    let pow_bits = 20;
    let field_hash = FieldHash::default();
    let compress = Compress::default();
    let whir_params = ProtocolParameters {
        security_level,
        pow_bits,
        folding_factor: FoldingFactor::Constant(4),
        merkle_hash: field_hash,
        merkle_compress: compress,
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
        rs_domain_initial_reduction_factor: 3,
    };
    let config = HyperPlonkConfig::<_, Challenge, _>::new(
        Pcs::new(dft, whir_params),
        Challenger::from_hasher(Vec::new(), Keccak256Hash),
    );

    for log_b in [15usize] {
        group.bench_with_input(
            BenchmarkId::new("prove_with_witness", log_b),
            &log_b,
            |b, log_b| {
                b.iter_batched(
                    || {
                        let mut rng = StdRng::from_seed([42u8; 32]);
                        generate_trace_rows::<
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
                        )
                    },
                    |trace| {
                        let prover_inputs = vec![ProverInput::new(&air, Vec::new(), trace)];
                        prove(&config, &pk, prover_inputs);
                    },
                    BatchSize::LargeInput,
                );
            },
        );

        let mut rng = StdRng::from_seed([7u8; 32]);
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
        let prover_inputs = vec![ProverInput::new(&air, Vec::new(), trace)];
        let proof = prove(&config, &pk, prover_inputs);

        group.bench_with_input(BenchmarkId::new("verify_only", log_b), &log_b, |b, _| {
            b.iter(|| {
                let verifier_inputs = vec![VerifierInput::new(&air, Vec::new())];
                verify(&config, &vk, verifier_inputs, &proof).unwrap();
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
