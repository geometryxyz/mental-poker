pub mod proof;
pub mod prover;
pub mod test;

use crate::error::Error;
use crate::zkp::ArgumentOfKnowledge;
use ark_ec::ProjectiveCurve;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

pub struct SchnorrIdentification<'a, C: ProjectiveCurve> {
    _group: PhantomData<&'a C>,
}

pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
}

impl<C: ProjectiveCurve> Parameters<C> {
    pub fn new(generator: C::Affine) -> Self {
        Self { generator }
    }
}

pub struct Statement<'a, C: ProjectiveCurve> {
    pub statement: &'a C,
}

impl<'a, C: ProjectiveCurve> Statement<'a, C> {
    pub fn new(to_prove: &'a C) -> Self {
        Self {
            statement: to_prove,
        }
    }
}

pub struct Witness<'a, C: ProjectiveCurve> {
    pub discrete_log_representation: &'a C::ScalarField,
}

impl<'a, C: ProjectiveCurve> Witness<'a, C> {
    pub fn new(discrete_log_representation: &'a C::ScalarField) -> Self {
        Self {
            discrete_log_representation,
        }
    }
}

impl<'a, C: ProjectiveCurve> ArgumentOfKnowledge for SchnorrIdentification<'a, C> {
    type CommonReferenceString = Parameters<C>;
    type Statement = Statement<'a, C>;
    type Witness = Witness<'a, C>;
    type Proof = proof::Proof<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::CommonReferenceString, Error> {
        let generator = C::rand(rng).into_affine();
        let parameters = Parameters::<C>::new(generator);

        Ok(parameters)
    }

    fn prove(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, Error> {
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
    ) -> Result<(), Error> {
        proof.verify(common_reference_string, statement)
    }
}
