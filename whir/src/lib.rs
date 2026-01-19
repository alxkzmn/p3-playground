#![no_std]

extern crate alloc;

mod keccak;
mod linear_constraints;
mod pcs;

pub use keccak::*;
pub use linear_constraints::*;
pub use pcs::*;
pub use whir_p3::parameters::errors::SecurityAssumption;
pub use whir_p3::parameters::{FoldingFactor, ProtocolParameters};
pub use whir_p3::whir::parameters::InitialPhaseConfig;

/// Convenience alias for the Keccak-based PCS instantiation.
pub type WhirPcsKeccak<Val, Dft, Hash, Compression> =
    WhirPcs<Val, Dft, Hash, Compression, 4, pcs::KeccakFlavor>;
