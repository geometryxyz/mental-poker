use ark_ec::ProjectiveCurve;
use crate::error::UtilError;
use std::marker::PhantomData;
use ark_ff::PrimeField;
use crypto_primitives::homomorphic_encryption::{
    el_gamal, MulByScalar,
};

pub trait DotProduct<C: ProjectiveCurve> {
    type Scalar;
    type Point;
    type Ciphertext;

    fn scalars_by_ciphers(
        scalars: &Vec<Self::Scalar>,
        ciphers: &Vec<Self::Ciphertext>,
    ) -> Result<Self::Ciphertext, UtilError>;

    fn scalars_by_points(
        scalars: &Vec<Self::Scalar>,
        points: &Vec<Self::Point>,
    ) -> Result<Self::Point, UtilError>;

    fn scalars_by_scalars(
        scalars_a: &Vec<Self::Scalar>,
        scalar_b: &Vec<Self::Scalar>,
    ) -> Result<Self::Scalar, UtilError>;
}

pub struct DotProductCalculator<C: ProjectiveCurve> {
    _curve: PhantomData<C>,
}

impl<C: ProjectiveCurve> DotProduct<C> for DotProductCalculator<C> {
    type Scalar = C::ScalarField;
    type Point = C;
    type Ciphertext = el_gamal::Ciphertext<C>;

    fn scalars_by_ciphers(
        scalars: &Vec<Self::Scalar>,
        ciphers: &Vec<Self::Ciphertext>,
    ) -> Result<Self::Ciphertext, UtilError> {
        if ciphers.len() != scalars.len() {
            return Err(UtilError::LengthError(String::from("Dot Product"), ciphers.len(), scalars.len()));
        }

        let dot_product: Self::Ciphertext = ciphers
            .iter()
            .zip(scalars.iter())
            .map(|(cipher, &scalar)| cipher.mul(scalar))
            .sum();

        Ok(dot_product)
    }

    fn scalars_by_points(
        scalars: &Vec<Self::Scalar>,
        points: &Vec<Self::Point>,
    ) -> Result<Self::Point, UtilError> {
        if points.len() != scalars.len() {
            return Err(UtilError::LengthError(String::from("Dot Product"), points.len(), scalars.len()));
        }

        let dot_product: Self::Point = points
            .iter()
            .zip(scalars.iter())
            .map(|(&point, scalar)| point.mul(scalar.into_repr()))
            .sum();

        Ok(dot_product)
    }

    fn scalars_by_scalars(
        scalars_a: &Vec<Self::Scalar>,
        scalars_b: &Vec<Self::Scalar>,
    ) -> Result<Self::Scalar, UtilError> {
        if scalars_a.len() != scalars_b.len() {
            return Err(UtilError::LengthError(String::from("Dot Product"), scalars_a.len(), scalars_b.len()));
        }

        let dot_product: Self::Scalar = scalars_a
            .iter()
            .zip(scalars_b.iter())
            .map(|(s_a, s_b)| *s_a * *s_b)
            .sum();

        Ok(dot_product)
    }
}

pub trait HadamardProduct<C: ProjectiveCurve> {
    type Scalar;

    fn scalars_by_scalars(
        scalars_a: &Vec<Self::Scalar>,
        scalars_b: &Vec<Self::Scalar>,
    ) -> Result<Vec<Self::Scalar>, UtilError>;
}

pub struct HadamardProductCalculator<C: ProjectiveCurve> {
    _curve: PhantomData<C>,
}

impl<C: ProjectiveCurve> HadamardProduct<C> for HadamardProductCalculator<C> {
    type Scalar = C::ScalarField;

    fn scalars_by_scalars(
        scalars_a: &Vec<Self::Scalar>,
        scalars_b: &Vec<Self::Scalar>,
    ) -> Result<Vec<Self::Scalar>, UtilError> {
        if scalars_a.len() != scalars_b.len() {
            return Err(UtilError::LengthError(String::from("Hadamard Product"), scalars_a.len(), scalars_b.len()));

        }

        let hadamard_product: Vec<Self::Scalar> = scalars_a
            .iter()
            .zip(scalars_b.iter())
            .map(|(&s_a, &s_b)| s_a * s_b)
            .collect();

        Ok(hadamard_product)
    }
}
