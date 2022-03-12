use crate::error::CryptoError;
use crate::utils::ops::{MulByScalar, ToField};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use std::ops;

pub mod el_gamal;

/// Trait defining the types and functions needed for an additively homomorphic encryption scheme.
/// The scheme is defined with respect to a finite field `F` for which scalar multiplication is preserved.
pub trait HomomorphicEncryptionScheme<F: Field> {
    type Parameters: CanonicalSerialize + CanonicalDeserialize;
    type PublicKey: CanonicalSerialize + CanonicalDeserialize;
    type SecretKey: CanonicalSerialize + CanonicalDeserialize;

    /// Represent the randomness used when performing encryption. This randomness must be part of the scalar field.
    type Randomness: ToField<F> + CanonicalSerialize + CanonicalDeserialize;

    /// Represent a plaintext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Plaintext: ops::Add
        + MulByScalar<F, Self::Randomness>
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Represent a ciphertext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Ciphertext: ops::Add
        + MulByScalar<F, Self::Randomness>
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Generate the scheme's parameters.
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, CryptoError>;

    /// Generate a public key and a private key.
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError>;

    /// Encrypt a message using the provided public key and randomness.
    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, CryptoError>;

    /// Recover a message from the provided ciphertext using a private key.
    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, CryptoError>;
}
