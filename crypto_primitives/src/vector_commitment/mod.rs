pub mod pedersen;
use crate::error::CryptoError;
use ark_ec::ProjectiveCurve;
use rand::Rng;

pub trait HomomorphicCommitment<C: ProjectiveCurve> {
    type CommitKey;

    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> Self::CommitKey;

    fn commit(
        commit_key: &Self::CommitKey,
        x: &Vec<C::ScalarField>,
        r: C::ScalarField,
    ) -> Result<C, CryptoError>;
}
