pub mod proof;
pub mod prover;
pub mod tests;

use crate::error::Error;
use ark_ec::ProjectiveCurve;
use std::iter;

/// Parameters for the zero argument for a bilinear map. Contains a commitment key and the matrix dimensions.
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

/// Witness for the zero argument for a bilinear map. Contains a matrix A, a vector r, a matrix B and a vector s such that:
/// `commitment_to_a` (see `Statement`) is a vector of commitments to the columns of A using randoms r, `commitment_to_b`
/// (see `Statement`) is a vector of commitments to the columns of B using randoms s and the sum of the column-wise application
/// of the bilinear map to A and B is 0.
pub struct Witness<'a, C: ProjectiveCurve> {
    pub matrix_a: &'a Vec<Vec<C::ScalarField>>,
    pub randoms_for_a_commit: &'a Vec<C::ScalarField>,
    pub matrix_b: &'a Vec<Vec<C::ScalarField>>,
    pub randoms_for_b_commit: &'a Vec<C::ScalarField>,
}

impl<'a, C: ProjectiveCurve> Witness<'a, C> {
    pub fn new(
        matrix_a: &'a Vec<Vec<C::ScalarField>>,
        randoms_for_a_commit: &'a Vec<C::ScalarField>,
        matrix_b: &'a Vec<Vec<C::ScalarField>>,
        randoms_for_b_commit: &'a Vec<C::ScalarField>,
    ) -> Self {
        Self {
            matrix_a,
            randoms_for_a_commit,
            matrix_b,
            randoms_for_b_commit,
        }
    }
}

/// Statement for the zero argument for a bilinear map. Contains a vector `commitment_to_a` of commitments to the columns
/// of matrix `A` using the randoms `r` (see `Witness`), a vector `commitment_to_b` of commitments to the columns of matrix
/// B using the randoms `s` (see `Witness`) and a bilinear map Z^n x Z^n -> Z.
pub struct Statement<'a, C: ProjectiveCurve> {
    pub commitment_to_a: &'a Vec<C>,
    pub commitment_to_b: &'a Vec<C>,
    pub bilinear_map: &'a YMapping<C>,
}

impl<'a, C: ProjectiveCurve> Statement<'a, C> {
    pub fn new(
        commitment_to_a: &'a Vec<C>,
        commitment_to_b: &'a Vec<C>,
        bilinear_map: &'a YMapping<C>,
    ) -> Self {
        Self {
            commitment_to_a,
            commitment_to_b,
            bilinear_map,
        }
    }
}

pub trait BilinearMap<C: ProjectiveCurve> {
    type Element;

    fn compute_mapping(
        &self,
        a: &Vec<Self::Element>,
        b: &Vec<Self::Element>,
    ) -> Result<Self::Element, Error>;
}

pub struct YMapping<C: ProjectiveCurve> {
    powers: Vec<C::ScalarField>,
}

impl<C: ProjectiveCurve> YMapping<C> {
    pub fn new(y: C::ScalarField, n: usize) -> Self {
        let powers = iter::once(y)
            .chain((1..n).scan(y, |current_power, _exp| {
                *current_power *= y;
                Some(*current_power)
            }))
            .collect::<Vec<_>>();

        Self { powers }
    }
}

impl<C: ProjectiveCurve> BilinearMap<C> for YMapping<C> {
    type Element = C::ScalarField;

    fn compute_mapping(
        &self,
        a: &Vec<Self::Element>,
        b: &Vec<Self::Element>,
    ) -> Result<Self::Element, Error> {
        if a.len() != b.len() || a.len() != self.powers.len() {
            return Err(Error::BilinearMapLenError);
        }

        let result: Self::Element = a
            .iter()
            .zip(b.iter())
            .enumerate()
            .map(|(i, (&a_i, &b_i))| a_i * b_i * self.powers[i])
            .sum();

        Ok(result)
    }
}
