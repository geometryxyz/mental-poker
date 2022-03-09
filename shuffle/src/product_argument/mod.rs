pub mod hadamard_product_argument;
pub mod single_value_product_argument;
pub mod zero_argument;

pub mod proof;
pub mod prover;
pub mod tests;

use ark_ec::ProjectiveCurve;

/// Parameters for the product argument
pub struct Parameters<'a, C: ProjectiveCurve> {
    pub commit_key: &'a Vec<C::Affine>,
    pub m: usize,
    pub n: usize,
}

impl<'a, C: ProjectiveCurve> Parameters<'a, C> {
    pub fn new(m: usize, n: usize, commit_key: &'a Vec<C::Affine>) -> Self {
        Self { commit_key, m, n }
    }
}

/// Witness for the product argument. Contains a matrix A for which we want to claim the product b (see `Statement`)
/// and randoms which will have been used to commit to each column of A.
pub struct Witness<'a, C: ProjectiveCurve> {
    pub matrix_a: &'a Vec<Vec<C::ScalarField>>,
    pub randoms_for_a_commit: &'a Vec<C::ScalarField>,
}

impl<'a, C: ProjectiveCurve> Witness<'a, C> {
    pub fn new(
        matrix_a: &'a Vec<Vec<C::ScalarField>>,
        randoms_for_a_commit: &'a Vec<C::ScalarField>,
    ) -> Self {
        Self {
            matrix_a,
            randoms_for_a_commit,
        }
    }
}

/// Statement for the product argument. Contains a vector of commitments to the columns of matrix A (see `Witness`)
/// and a scalar b which is claimed to be the product of all the cells in A.
pub struct Statement<'a, C: ProjectiveCurve> {
    pub commitments_to_a: &'a Vec<C>,
    pub b: C::ScalarField,
}

impl<'a, C: ProjectiveCurve> Statement<'a, C> {
    pub fn new(commitments_to_a: &'a Vec<C>, b: C::ScalarField) -> Self {
        Self {
            commitments_to_a,
            b,
        }
    }
}
