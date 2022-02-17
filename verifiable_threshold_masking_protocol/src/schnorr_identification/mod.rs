pub mod prover;
pub mod proof;
pub mod transcript;
pub mod error;
// pub mod verifier;

use ark_ec::{ProjectiveCurve};

pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
}