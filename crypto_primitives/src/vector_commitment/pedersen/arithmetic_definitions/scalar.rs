use super::super::Scalar;
use crate::utils::ops::FromField;
use ark_ec::ProjectiveCurve;
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use rand::Rng;

impl<C: ProjectiveCurve> Scalar<C> {
    pub fn into_scalarfield(self) -> C::ScalarField {
        self.0
    }

    pub fn from(x: C::ScalarField) -> Self {
        Self(x)
    }
}

impl<C: ProjectiveCurve> std::ops::Add<Scalar<C>> for Scalar<C> {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self {
        Self(self.0 + _rhs.0)
    }
}

impl<C: ProjectiveCurve> std::ops::Mul<Scalar<C>> for Scalar<C> {
    type Output = Self;

    fn mul(self, _rhs: Self) -> Self {
        Self(self.0 * _rhs.0)
    }
}

impl<C: ProjectiveCurve> UniformRand for Scalar<C> {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self::from_field(C::ScalarField::rand(rng))
    }
}

impl<C: ProjectiveCurve> Zero for Scalar<C> {
    fn zero() -> Self {
        Self(C::ScalarField::zero())
    }

    fn is_zero(&self) -> bool {
        *self == Self(C::ScalarField::zero())
    }
}

impl<C: ProjectiveCurve> One for Scalar<C> {
    fn one() -> Self {
        Self(C::ScalarField::one())
    }
}
