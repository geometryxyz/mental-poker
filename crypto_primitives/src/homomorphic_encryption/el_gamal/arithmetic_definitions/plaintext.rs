use super::super::{Plaintext, Randomness};
use crate::utils::ops::MulByScalar;
use crate::utils::ops::ToField;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::Zero;
use ark_std::rand::Rng;
use ark_std::UniformRand;

impl<C: ProjectiveCurve> MulByScalar<C::ScalarField, Randomness<C>> for Plaintext<C> {
    type Output = Self;

    fn mul(self, scalar: Randomness<C>) -> Self::Output {
        Self(self.0.mul(scalar.into_field()).into_affine())
    }

    fn mul_in_place(&mut self, scalar: Randomness<C>) {
        self.0 = self.0.mul(scalar.into_field()).into_affine();
    }
}

impl<C: ProjectiveCurve> std::ops::Add<Plaintext<C>> for Plaintext<C> {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self {
        Self(self.0 + _rhs.0)
    }
}

impl<C: ProjectiveCurve> Plaintext<C> {
    pub fn from_affine(point: C::Affine) -> Self {
        Self(point)
    }

    pub fn from_projective(point: C) -> Self {
        Self(point.into())
    }

    pub fn into_affine(self) -> C::Affine {
        self.0
    }
}

impl<C: ProjectiveCurve> UniformRand for Plaintext<C> {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self::from_projective(C::rand(rng))
    }
}

impl<C: ProjectiveCurve> Zero for Plaintext<C> {
    fn zero() -> Self {
        Self(C::Affine::zero())
    }

    fn is_zero(&self) -> bool {
        self.0 == C::Affine::zero()
    }
}
