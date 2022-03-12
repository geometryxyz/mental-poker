use super::super::{Commitment, Scalar};
use crate::utils::ops::MulByScalar;
use crate::utils::ops::ToField;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_std::UniformRand;
use rand::Rng;

impl<C: ProjectiveCurve> MulByScalar<C::ScalarField, Scalar<C>> for Commitment<C> {
    type Output = Self;

    fn mul(self, scalar: Scalar<C>) -> Self::Output {
        Self(self.0.mul(scalar.into_field()).into_affine())
    }

    fn mul_in_place(&mut self, scalar: Scalar<C>) {
        self.0 = self.0.mul(scalar.into_field()).into_affine();
    }
}

impl<C: ProjectiveCurve> std::ops::Add<Commitment<C>> for Commitment<C> {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self {
        Self(self.0 + _rhs.0)
    }
}

impl<C: ProjectiveCurve> Commitment<C> {
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

impl<C: ProjectiveCurve> UniformRand for Commitment<C> {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self::from_projective(C::rand(rng))
    }
}
