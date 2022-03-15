pub mod proof;
pub mod prover;
mod test;

use crate::error::CryptoError;
use crate::zkp::ArgumentOfKnowledge;
use ark_ec::ProjectiveCurve;
use ark_std::marker::PhantomData;
// use ark_std::rand::Rng;

pub struct SchnorrIdentification<'a, C: ProjectiveCurve> {
    _group: PhantomData<&'a C>,
}

pub type Parameters<C> = <C as ProjectiveCurve>::Affine;

pub type Statement<C> = <C as ProjectiveCurve>::Affine;

pub type Witness<C> = <C as ProjectiveCurve>::ScalarField;

impl<'a, C: ProjectiveCurve> ArgumentOfKnowledge for SchnorrIdentification<'a, C> {
    type CommonReferenceString = Parameters<C>;
    type Statement = Statement<C>;
    type Witness = Witness<C>;
    type Proof = proof::Proof<C>;

    // fn setup<R: Rng>(rng: &mut R) -> Result<Self::CommonReferenceString, CryptoError> {
    //     Ok(C::rand(rng).into_affine())
    // }

    fn prove(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, CryptoError> {
        Ok(prover::Prover::create_proof(
            common_reference_string,
            statement,
            witness,
        ))
    }

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
    ) -> Result<(), CryptoError> {
        proof.verify(common_reference_string, statement)
    }
}
