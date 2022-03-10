use crate::error::CryptoError;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use std::ops;

pub mod el_gamal;

pub trait HomomorphicEncryptionScheme {
    type Parameters: CanonicalSerialize;
    type PublicKey: CanonicalSerialize;
    type SecretKey: CanonicalSerialize;
    type Randomness: Field + CanonicalSerialize;
    type Plaintext: CanonicalSerialize;
    type Ciphertext: ops::Add + MulByScalar<Self::Randomness> + CanonicalSerialize;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, CryptoError>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError>;

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, CryptoError>;

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, CryptoError>;
}

pub trait MulByScalar<Rhs: Field> {
    type Output;

    fn mul(self, rhs: Rhs) -> Self::Output;
    fn mul_in_place(&mut self, rhs: Rhs);
}
