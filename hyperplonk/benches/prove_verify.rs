use std::sync::atomic::{Ordering, compiler_fence};

use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use p3_air::{Air, AirBuilder, BaseAir, BaseAirWithPublicValues};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_hyperplonk::{HyperPlonkConfig, ProverInput, VerifierInput, keygen, prove, verify};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_poseidon2_air::{RoundConstants, generate_trace_rows, num_cols};
use p3_whir::{
    FoldingFactor, InitialPhaseConfig, KeccakNodeCompress, KeccakU32BeLeafHasher,
    ProtocolParameters, SecurityAssumption, WhirPcsKeccak,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[cfg(target_family = "unix")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

type Val = KoalaBear;
type Challenge = BinomialExtensionField<Val, 4>;
type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;

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
    let mut rng = StdRng::from_seed([0u8; 32]);

    let config = {
        let dft = Dft::default();
        // FIXME: Set to 128 when higher degree extension field is available.
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
    let air = &Poseidon2Air(p3_poseidon2_air::Poseidon2Air::new(round_constants.clone()));
    let (vk, pk) = keygen([&air]);

    for log_b in 15..16 {
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

        {
            let mut prove_group = c.benchmark_group("prove/koala_bear_poseidon2");
            prove_group.sample_size(10);
            prove_group.bench_with_input(BenchmarkId::from_parameter(log_b), &log_b, |b, _| {
                b.iter_batched(
                    || trace.clone(),
                    |trace| {
                        let prover_inputs = vec![ProverInput::new(air, Vec::new(), trace)];
                        prove(&config, &pk, prover_inputs)
                    },
                    BatchSize::LargeInput,
                );
            });
            prove_group.finish();
        }

        let proof = {
            let prover_inputs = vec![ProverInput::new(air, Vec::new(), trace.clone())];
            prove(&config, &pk, prover_inputs)
        };

        {
            let mut verify_group = c.benchmark_group("verify/koala_bear_poseidon2");
            verify_group.sample_size(10);
            verify_group.bench_with_input(BenchmarkId::from_parameter(log_b), &log_b, |b, _| {
                b.iter(|| {
                    compiler_fence(Ordering::SeqCst);
                    let verifier_inputs = vec![VerifierInput::new(air, Vec::new())];
                    let res = verify(
                        black_box(&config),
                        black_box(&vk),
                        black_box(verifier_inputs),
                        black_box(&proof),
                    );
                    compiler_fence(Ordering::SeqCst);
                    black_box(res.unwrap());
                });
            });
            verify_group.finish();
        }
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
