pub mod pedersen;

use crate::error::CryptoError;
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use std::{iter::Sum, ops};

/// Trait defining the types and functions needed for an additively homomorphic commitment scheme.
/// The scheme is defined with respect to a finite field `F` for which scalar multiplication is preserved.
pub trait HomomorphicCommitmentScheme<Scalar: Field> {
    type CommitKey: CanonicalSerialize + CanonicalDeserialize;

    /// Represent a ciphertext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Commitment: PartialEq
        + Copy
        + ops::Add
        + ops::Mul<Scalar, Output = Self::Commitment>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Zero
        + Sum;

    /// Generate a commit key using the provided length
    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> Self::CommitKey;

    /// Commit to a vector of scalars using the commit key
    fn commit(
        commit_key: &Self::CommitKey,
        x: &Vec<Scalar>,
        r: Scalar,
    ) -> Result<Self::Commitment, CryptoError>;
}
