use itertools::Itertools;
use p3_air::{Air, BaseAirWithPublicValues};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};
use p3_hyperplonk::{
    HyperPlonkConfig, ProverConstraintFolderOnExtension, ProverConstraintFolderOnExtensionPacking,
    ProverConstraintFolderOnPacking, ProverInput, ProverInteractionFolderOnExtension,
    ProverInteractionFolderOnPacking, SymbolicAirBuilder, VerifierConstraintFolder, keygen, prove,
    verify,
};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_whir::{
    FoldingFactor, InitialPhaseConfig, KeccakNodeCompress, KeccakU32BeLeafHasher,
    ProtocolParameters, SecurityAssumption, WhirPcsKeccak,
};

type Val = KoalaBear;
type FieldHash = KeccakU32BeLeafHasher;
type MyCompress = KeccakNodeCompress;
type Dft<Val> = Radix2DitParallel<Val>;
type Pcs<Val, Dft> = WhirPcsKeccak<Val, Dft, FieldHash, MyCompress>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>;

#[allow(clippy::multiple_bound_locations)]
pub fn run<
    Challenge,
    #[cfg(feature = "check-constraints")] A: for<'a> Air<p3_air_ext::DebugConstraintBuilder<'a, Val>>,
    #[cfg(not(feature = "check-constraints"))] A,
>(
    prover_inputs: Vec<ProverInput<KoalaBear, A>>,
) where
    KoalaBear: TwoAdicField + PrimeField32,
    Challenge: TwoAdicField + ExtensionField<KoalaBear>,
    A: Clone
        + BaseAirWithPublicValues<KoalaBear>
        + Air<SymbolicAirBuilder<KoalaBear>>
        + for<'t> Air<ProverInteractionFolderOnExtension<'t, KoalaBear, Challenge>>
        + for<'t> Air<ProverInteractionFolderOnPacking<'t, KoalaBear, Challenge>>
        + for<'t> Air<ProverConstraintFolderOnPacking<'t, KoalaBear, Challenge>>
        + for<'t> Air<ProverConstraintFolderOnExtension<'t, KoalaBear, Challenge>>
        + for<'t> Air<ProverConstraintFolderOnExtensionPacking<'t, KoalaBear, Challenge>>
        + for<'t> Air<VerifierConstraintFolder<'t, KoalaBear, Challenge>>,
{
    let config = {
        let dft = Dft::default();
        let security_level = 60;
        let pow_bits = 0;
        let field_hash = FieldHash::default();
        let compress = MyCompress::default();
        let whir_params = ProtocolParameters {
            initial_phase_config: InitialPhaseConfig::WithStatementClassic,
            security_level,
            pow_bits,
            folding_factor: FoldingFactor::Constant(4),
            merkle_hash: field_hash,
            merkle_compress: compress,
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 3,
        };
        HyperPlonkConfig::<_, Challenge, _>::new(
            Pcs::new(dft, whir_params),
            Challenger::from_hasher(Vec::new(), Keccak256Hash),
        )
    };

    let verifier_inputs = prover_inputs
        .iter()
        .map(|input| input.to_verifier_input())
        .collect_vec();

    let (vk, pk) = keygen(verifier_inputs.iter().map(|input| input.air()));

    let proof = prove(&config, &pk, prover_inputs);

    verify(&config, &vk, verifier_inputs, &proof).unwrap();
}
