use super::super::Scalar;
use ark_ec::ProjectiveCurve;

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
