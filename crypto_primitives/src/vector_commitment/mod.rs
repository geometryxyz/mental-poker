pub mod pedersen;
use crate::error::CryptoError;
use crate::utils::ops::MulByScalar;
use crate::utils::ops::ToField;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use std::ops;

pub trait HomomorphicCommitmentScheme<F: Field> {
    type CommitKey: CanonicalSerialize + CanonicalDeserialize;
    type Commitment: ops::Add
        + MulByScalar<F, Self::Scalar>
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Scalar: ops::Add + ops::Mul + ToField<F> + CanonicalSerialize + CanonicalDeserialize;

    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> Self::CommitKey;

    fn commit(
        commit_key: &Self::CommitKey,
        x: &Vec<Self::Scalar>,
        r: Self::Scalar,
    ) -> Result<Self::Commitment, CryptoError>;
}
