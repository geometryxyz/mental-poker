use crate::error::CryptoError;
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use std::iter::Sum;
use std::ops;

pub mod el_gamal;

/// Trait defining the types and functions needed for an additively homomorphic encryption scheme.
/// The scheme is defined with respect to a finite field `F` for which scalar multiplication is preserved.
pub trait HomomorphicEncryptionScheme<Scalar: Field> {
    type Parameters: CanonicalSerialize + CanonicalDeserialize;
    type PublicKey: CanonicalSerialize + CanonicalDeserialize;
    type SecretKey: CanonicalSerialize + CanonicalDeserialize;

    /// Represent a plaintext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Plaintext: Copy
        + ops::Add
        + ops::Mul<Scalar, Output = Self::Plaintext>
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Represent a ciphertext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Ciphertext: Copy
        + PartialEq
        + ops::Add<Output = Self::Ciphertext>
        + ops::Mul<Scalar, Output = Self::Ciphertext>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Sum
        + Zero;

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
        r: &Scalar,
    ) -> Result<Self::Ciphertext, CryptoError>;

    /// Recover a message from the provided ciphertext using a private key.
    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, CryptoError>;
}
