pub mod error;
pub mod proof;
pub mod prover;
pub mod transcript;
// pub mod verifier;

use ark_ec::ProjectiveCurve;

pub struct Parameters<C: ProjectiveCurve> {
    pub g: C::Affine,
    pub h: C::Affine,
}
