use super::Ciphertext;
use crate::homomorphic_encryption::MulByScalar;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    Zero,
};

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

impl<C: ProjectiveCurve> MulByScalar<C::ScalarField> for Ciphertext<C> {
    type Output = Self;

    fn mul(self, scalar: C::ScalarField) -> Self::Output {
        Self(
            self.0.mul(scalar).into_affine(),
            self.1.mul(scalar).into_affine(),
        )
    }

    fn mul_in_place(&mut self, scalar: C::ScalarField) {
        self.0 = self.0.mul(scalar).into_affine();
        self.1 = self.1.mul(scalar).into_affine();
    }
}

impl<C: ProjectiveCurve> CanonicalSerialize for Ciphertext<C> {
    #[inline]
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.0.serialize(&mut writer)?;
        self.1.serialize(writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.0.serialized_size() + self.1.serialized_size()
    }

    #[inline]
    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.0.serialize_uncompressed(&mut writer)?;
        self.1.serialize_uncompressed(writer)?;
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        self.0.uncompressed_size() + self.1.uncompressed_size()
    }
}

impl<C: ProjectiveCurve> CanonicalDeserialize for Ciphertext<C> {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let c0 = C::Affine::deserialize(&mut reader)?;
        let c1 = C::Affine::deserialize(&mut reader)?;

        Ok(Self(c0, c1))
    }

    fn deserialize_uncompressed<R: Read>(
        mut reader: R,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let c0 = C::Affine::deserialize_uncompressed(&mut reader)?;
        let c1 = C::Affine::deserialize_uncompressed(&mut reader)?;

        Ok(Self(c0, c1))
    }

    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let c0 = C::Affine::deserialize_unchecked(&mut reader)?;
        let c1 = C::Affine::deserialize_unchecked(&mut reader)?;

        Ok(Self(c0, c1))
    }
}

#[cfg(test)]
mod test {

    use super::*;
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
