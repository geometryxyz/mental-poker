pub mod prover;
pub mod proof;
pub mod tests;

use ark_ec::{ProjectiveCurve};


/// Parameters for the Hadamard product argument. Contains a commitment key and the matrix dimensions.
pub struct Parameters<'a, C: ProjectiveCurve> {
    pub commit_key: &'a Vec<C::Affine>,
    pub m: usize,
    pub n: usize
}

impl<'a, C: ProjectiveCurve> Parameters<'a, C> {
    pub fn new(m: usize, n: usize, commit_key: &'a Vec<C::Affine>) -> Self {
        Self {
            commit_key,
            m,
            n,
        }
    }
}

pub struct Witness<'a, C: ProjectiveCurve> {
    pub matrix_a: &'a Vec<Vec<C::ScalarField>>,
    pub randoms_for_a_commit: &'a Vec<C::ScalarField>,
    pub vector_b: &'a Vec<C::ScalarField>,
    pub random_for_b_commit: C::ScalarField,
}

impl<'a, C: ProjectiveCurve> Witness<'a, C> {
    pub fn new(
        matrix_a: &'a Vec<Vec<C::ScalarField>>,
        randoms_for_a_commit: &'a Vec<C::ScalarField>,
        vector_b: &'a Vec<C::ScalarField>,
        random_for_b_commit: C::ScalarField,
    ) -> Self {
        Self {
            matrix_a, 
            randoms_for_a_commit, 
            vector_b, 
            random_for_b_commit, 
        }
    }
}


pub struct Statement<'a, C: ProjectiveCurve> {
    pub commitment_to_a: &'a Vec<C>,
    pub commitment_to_b: C,
}

impl<'a, C: ProjectiveCurve> Statement<'a, C> {
    pub fn new(commitment_to_a: &'a Vec<C>, commitment_to_b: C) -> Self {
        Self {
            commitment_to_a, 
            commitment_to_b,
        }
    }
}