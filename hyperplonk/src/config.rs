use core::marker::PhantomData;

use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_field::ExtensionField;
use p3_ml_pcs::MlPcs;

pub type PcsError<SC> = <<SC as HyperPlonkGenericConfig>::Pcs as MlPcs<
    <SC as HyperPlonkGenericConfig>::Challenge,
    <SC as HyperPlonkGenericConfig>::Challenger,
>>::Error;

pub type Val<C> = <<C as HyperPlonkGenericConfig>::Pcs as MlPcs<
    <C as HyperPlonkGenericConfig>::Challenge,
    <C as HyperPlonkGenericConfig>::Challenger,
>>::Val;

pub const DEFAULT_UNIVARIATE_SKIP_ROUNDS: usize = 6;

pub trait HyperPlonkGenericConfig {
    /// The PCS used to commit to trace polynomials.
    type Pcs: MlPcs<Self::Challenge, Self::Challenger>;

    /// The field from which most random challenges are drawn.
    type Challenge: ExtensionField<Val<Self>>;

    /// The challenger (Fiat-Shamir) implementation used.
    type Challenger: FieldChallenger<Val<Self>>
        + CanObserve<<Self::Pcs as MlPcs<Self::Challenge, Self::Challenger>>::Commitment>
        + CanSample<Self::Challenge>;

    /// Get a reference to the PCS used by this proof configuration.
    fn pcs(&self) -> &Self::Pcs;

    /// Get an initialization of the challenger used by this proof configuration.
    fn initialize_challenger(&self) -> Self::Challenger;

    /// Number of univariate skip rounds to use in the prover's AIR sumcheck path.
    fn univariate_skip_rounds(&self) -> usize {
        DEFAULT_UNIVARIATE_SKIP_ROUNDS
    }
}

#[derive(Debug)]
pub struct HyperPlonkConfig<Pcs, Challenge, Challenger> {
    /// The PCS used to commit polynomials and prove opening proofs.
    pcs: Pcs,
    /// An initialized instance of the challenger.
    challenger: Challenger,
    /// Number of rounds to skip in univariate AIR sumcheck.
    univariate_skip_rounds: usize,
    _phantom: PhantomData<Challenge>,
}

impl<Pcs, Challenge, Challenger> HyperPlonkConfig<Pcs, Challenge, Challenger> {
    pub const fn new(pcs: Pcs, challenger: Challenger) -> Self {
        Self {
            pcs,
            challenger,
            univariate_skip_rounds: DEFAULT_UNIVARIATE_SKIP_ROUNDS,
            _phantom: PhantomData,
        }
    }

    pub const fn with_univariate_skip_rounds(mut self, univariate_skip_rounds: usize) -> Self {
        self.univariate_skip_rounds = univariate_skip_rounds;
        self
    }

    pub const fn get_univariate_skip_rounds(&self) -> usize {
        self.univariate_skip_rounds
    }
}

impl<Pcs, Challenge, Challenger> HyperPlonkGenericConfig
    for HyperPlonkConfig<Pcs, Challenge, Challenger>
where
    Challenge: ExtensionField<Pcs::Val>,
    Pcs: MlPcs<Challenge, Challenger>,
    Challenger: FieldChallenger<Pcs::Val>
        + CanObserve<<Pcs as MlPcs<Challenge, Challenger>>::Commitment>
        + CanSample<Challenge>
        + Clone,
{
    type Pcs = Pcs;
    type Challenge = Challenge;
    type Challenger = Challenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialize_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }

    fn univariate_skip_rounds(&self) -> usize {
        self.univariate_skip_rounds
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_keccak::Keccak256Hash;
    use p3_koala_bear::KoalaBear;
    use p3_whir::{
        FoldingFactor, KeccakNodeCompress, KeccakU32BeLeafHasher, ProtocolParameters,
        SecurityAssumption, WhirPcs,
    };

    use super::{DEFAULT_UNIVARIATE_SKIP_ROUNDS, HyperPlonkConfig, HyperPlonkGenericConfig};

    type Val = KoalaBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type Dft = Radix2DitParallel<Val>;
    type FieldHash = KeccakU32BeLeafHasher;
    type Compress = KeccakNodeCompress;
    type Pcs = WhirPcs<Val, Dft, FieldHash, Compress, 4>;
    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>;

    fn make_config() -> HyperPlonkConfig<Pcs, Challenge, Challenger> {
        let whir_params = ProtocolParameters {
            security_level: 100,
            pow_bits: 0,
            folding_factor: FoldingFactor::Constant(4),
            merkle_hash: FieldHash::for_security_bits(100),
            merkle_compress: Compress::for_security_bits(100),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 3,
        };
        HyperPlonkConfig::new(
            Pcs::new(Dft::default(), whir_params),
            Challenger::from_hasher(Vec::new(), Keccak256Hash),
        )
    }

    #[test]
    fn default_univariate_skip_is_6() {
        let config = make_config();
        assert_eq!(
            config.get_univariate_skip_rounds(),
            DEFAULT_UNIVARIATE_SKIP_ROUNDS
        );
    }

    #[test]
    fn builder_sets_univariate_skip_rounds() {
        let config = make_config().with_univariate_skip_rounds(3);
        assert_eq!(config.get_univariate_skip_rounds(), 3);
    }

    #[test]
    fn trait_accessor_returns_overridden_skip() {
        let config = make_config().with_univariate_skip_rounds(4);
        assert_eq!(HyperPlonkGenericConfig::univariate_skip_rounds(&config), 4);
    }
}
