use crate::error::Error;
use crate::homomorphic_encryption::HomomorphicEncryptionScheme;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

pub mod ciphertext_arithmetic;

pub struct ElGamal<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;

pub type Plaintext<C> = <C as ProjectiveCurve>::Affine;

pub type SecretKey<C> = <C as ProjectiveCurve>::ScalarField;

pub type Randomness<C> = <C as ProjectiveCurve>::ScalarField;

impl<C: ProjectiveCurve> CanonicalSerialize for Parameters<C> {
    #[inline]
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.generator.serialize(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.generator.serialized_size()
    }

    #[inline]
    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.generator.serialize_uncompressed(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        self.generator.uncompressed_size()
    }
}

impl<C: ProjectiveCurve> CanonicalDeserialize for Parameters<C> {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let generator = C::Affine::deserialize(&mut reader)?;

        Ok(Self { generator })
    }

    fn deserialize_uncompressed<R: Read>(
        mut reader: R,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let generator = C::Affine::deserialize_uncompressed(&mut reader)?;

        Ok(Self { generator })
    }

    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let generator = C::Affine::deserialize_unchecked(&mut reader)?;

        Ok(Self { generator })
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Ciphertext<C: ProjectiveCurve>(pub C::Affine, pub C::Affine);

impl<C: ProjectiveCurve> HomomorphicEncryptionScheme for ElGamal<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        // get a random generator
        let generator = C::rand(rng).into();

        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // get a random element from the scalar field
        let secret_key: <C as ProjectiveCurve>::ScalarField = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let public_key = pp.generator.mul(secret_key).into();

        Ok((public_key, secret_key))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, Error> {
        // compute s = r*pk
        let s = pk.mul(r.into_repr()).into();

        // compute c1 = r*generator
        let c1 = pp.generator.mul(r.into_repr()).into();

        // compute c2 = m + s
        let c2 = *message + s;

        Ok(Ciphertext(c1, c2))
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error> {
        let c1: <C as ProjectiveCurve>::Affine = ciphertext.0;
        let c2: <C as ProjectiveCurve>::Affine = ciphertext.1;

        // compute s = secret_key * c1
        let s = c1.mul(sk.into_repr());
        let s_inv = -s;

        // compute message = c2 - s
        let m = c2 + s_inv.into_affine();

        Ok(m)
    }
}
