pub mod prover;
pub mod proof;
pub mod tests;

use ark_ec::{ProjectiveCurve};
// pub mod verifier;

/// Parameters
pub struct Parameters<'a, C: ProjectiveCurve> {
    pub commit_key: &'a Vec<C::Affine>,
    pub n: usize
}

impl<'a, C: ProjectiveCurve> Parameters<'a, C> {
    pub fn new(n: usize, commit_key: &'a Vec<C::Affine>) -> Self {
        Self {
            commit_key,
            n,
        }
    }
}

/// Witness
pub struct Witness<'a, C: ProjectiveCurve> {
    pub a: &'a Vec<C::ScalarField>,
    pub random_for_a_commit: &'a C::ScalarField,
}

impl<'a, C: ProjectiveCurve> Witness<'a, C> {
    pub fn new(
        a: &'a Vec<C::ScalarField>,
        random_for_a_commit: &'a C::ScalarField
    ) -> Self {
        Self {
            a, 
            random_for_a_commit
        }
    }
}

/// Statement
pub struct Statement<C: ProjectiveCurve> {
    pub a_commit: C,
    pub b: C::ScalarField,
}

impl<'a, C: ProjectiveCurve> Statement<C> {
    pub fn new(a_commit: C, b: C::ScalarField) -> Self {
        Self {
            a_commit,
            b
        }
    }
}