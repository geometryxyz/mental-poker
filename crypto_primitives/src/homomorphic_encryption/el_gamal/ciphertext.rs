use super::{Ciphertext, Randomness};
use crate::utils::ops::{MulByScalar, ToField};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_std::{Zero, One};

impl<C: ProjectiveCurve> std::ops::Add<Ciphertext<C>> for Ciphertext<C> {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self {
        Self(self.0 + _rhs.0, self.1 + _rhs.1)
    }
}

impl<C: ProjectiveCurve> std::iter::Sum for Ciphertext<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(C::Affine::zero(), C::Affine::zero()), |a, b| a + b)
    }
}

impl<C: ProjectiveCurve> Zero for Ciphertext<C> {
    fn zero() -> Self {
        Self(C::Affine::zero(), C::Affine::zero())
    }

    fn is_zero(&self) -> bool {
        *self == Self(C::Affine::zero(), C::Affine::zero())
    }
}

impl<C: ProjectiveCurve> MulByScalar<C::ScalarField, Randomness<C>> for Ciphertext<C> {
    type Output = Self;

    fn mul(self, scalar: Randomness<C>) -> Self::Output {
        Self(
            self.0.mul(scalar.into_field()).into_affine(),
            self.1.mul(scalar.into_field()).into_affine(),
        )
    }

    fn mul_in_place(&mut self, scalar: Randomness<C>) {
        self.0 = self.0.mul(scalar.into_field()).into_affine();
        self.1 = self.1.mul(scalar.into_field()).into_affine();
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::UniformRand;
    use rand::thread_rng;
    use starknet_curve::Projective;

    #[test]
    fn serialize_unserialize_test() {
        let mut rng = thread_rng();
        let c0 = Projective::rand(&mut rng).into_affine();
        let c1 = Projective::rand(&mut rng).into_affine();

        let cipher = Ciphertext::<Projective>(c0, c1);

        let mut serialized = vec![0; cipher.serialized_size()];
        cipher.serialize(&mut serialized[..]).unwrap();

        let deserialized = Ciphertext::<Projective>::deserialize(&serialized[..]).unwrap();
        assert_eq!(cipher, deserialized);
    }
}
