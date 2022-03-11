use super::Randomness;
use ark_ec::ProjectiveCurve;
use rand::Rng;
use ark_ff::{One, Zero};
use crate::utils::ops::{ToField, FromField};
use ark_std::UniformRand;


impl<C: ProjectiveCurve> Randomness<C> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self::from_field(C::ScalarField::rand(rng))
    }
}

impl<C: ProjectiveCurve> std::ops::Neg for Randomness<C> {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl<C: ProjectiveCurve> std::ops::Add<Randomness<C>> for Randomness<C> {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self {
        Self(self.0 + _rhs.0)
    }
}

impl<C: ProjectiveCurve> std::ops::Mul<Randomness<C>> for Randomness<C> {
    type Output = Self;

    fn mul(self, _rhs: Self) -> Self {
        Self(self.0 * _rhs.0)
    }
}

impl<C: ProjectiveCurve> std::iter::Sum for Randomness<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(C::ScalarField::zero()), |a, b| a + b)
    }
}

impl<C: ProjectiveCurve> Zero for Randomness<C> {
    fn zero() -> Self {
        Self(C::ScalarField::zero())
    }

    fn is_zero(&self) -> bool {
        *self == Self(C::ScalarField::zero())
    }
}

impl<C: ProjectiveCurve> One for Randomness<C> {
    fn one() -> Self {
        Self(C::ScalarField::one())
    }
}


impl<C: ProjectiveCurve> ToField<C::ScalarField> for Randomness<C> {
    fn into_field(self) -> C::ScalarField {
        self.0
    }
}

impl<C: ProjectiveCurve> FromField<C::ScalarField> for Randomness<C> {
    fn from_field(x: C::ScalarField) -> Self {
        Self(x)
    }
}