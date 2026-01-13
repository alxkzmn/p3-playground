#![no_std]

extern crate alloc;

mod pcs;

pub use pcs::*;
#[cfg(feature = "keccak")]
pub use whir_p3::keccak_mmcs::*;
pub use whir_p3::parameters::errors::SecurityAssumption;
pub use whir_p3::parameters::{FoldingFactor, ProtocolParameters};
pub use whir_p3::whir::parameters::InitialPhaseConfig;

/// Convenience alias for the Keccak-based PCS instantiation.
#[cfg(feature = "keccak")]
pub type WhirPcsKeccak<Val, Dft, Hash, Compression> =
    WhirPcs<Val, Dft, Hash, Compression, 32, pcs::KeccakFlavor>;
