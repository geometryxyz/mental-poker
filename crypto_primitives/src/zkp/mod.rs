use crate::error::Error;
use ark_std::rand::Rng;

pub mod arguments;
pub mod proofs;
pub mod transcript;
pub mod utils;

pub trait ArgumentOfKnowledge {
    type CommonReferenceString;
    type Statement;
    type Witness;
    type Proof;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::CommonReferenceString, Error>;

    fn prove(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
    ) -> Result<(), Error>;
}
