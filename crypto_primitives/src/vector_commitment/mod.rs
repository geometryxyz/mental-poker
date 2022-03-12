pub mod pedersen;

use crate::error::CryptoError;
use crate::utils::ops::MulByScalar;
use crate::utils::ops::{FromField, ToField};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use std::ops;

/// Trait defining the types and functions needed for an additively homomorphic commitment scheme.
/// The scheme is defined with respect to a finite field `F` for which scalar multiplication is preserved.
pub trait HomomorphicCommitmentScheme<F: Field> {
    type CommitKey: CanonicalSerialize + CanonicalDeserialize;

    /// Represent a ciphertext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Commitment: ops::Add
        + MulByScalar<F, Self::Scalar>
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Scalars from the underlying finite field to which we will commit using our scheme.
    type Scalar: ops::Add
        + ops::Mul
        + ToField<F>
        + FromField<F>
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Generate a commit key using the provided length
    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> Self::CommitKey;

    /// Commit to a vector of scalars using the commit key
    fn commit(
        commit_key: &Self::CommitKey,
        x: &Vec<Self::Scalar>,
        r: Self::Scalar,
    ) -> Result<Self::Commitment, CryptoError>;
}
