use crate::error::CryptoError;
use crate::utils::ops::{MulByScalar, ToField};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use std::ops;

pub mod el_gamal;

pub trait HomomorphicEncryptionScheme<F: Field> {
    type Parameters: CanonicalSerialize + CanonicalDeserialize;
    type PublicKey: CanonicalSerialize + CanonicalDeserialize;
    type SecretKey: CanonicalSerialize + CanonicalDeserialize;
    type Randomness: ToField<F> + CanonicalSerialize + CanonicalDeserialize;
    type Plaintext: ops::Add
        + MulByScalar<F, Self::Randomness>
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Ciphertext: ops::Add
        + MulByScalar<F, Self::Randomness>
        + CanonicalSerialize
        + CanonicalDeserialize;

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
