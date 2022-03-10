pub mod proof;
pub mod prover;
mod test;

use crate::error::CryptoError;
use crate::zkp::ArgumentOfKnowledge;
use ark_ec::ProjectiveCurve;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

pub struct DLEquality<'a, C: ProjectiveCurve> {
    _group: PhantomData<&'a C>,
}

pub struct Parameters<C: ProjectiveCurve> {
    pub g: C::Affine,
    pub h: C::Affine,
}

impl<C: ProjectiveCurve> Parameters<C> {
    pub fn new(g: C::Affine, h: C::Affine) -> Self {
        Self { g, h }
    }
}

pub struct Statement<'a, C: ProjectiveCurve>(pub &'a C::Affine, pub &'a C::Affine);

impl<'a, C: ProjectiveCurve> Statement<'a, C> {
    pub fn new(point_a: &'a C::Affine, point_b: &'a C::Affine) -> Self {
        Self(point_a, point_b)
    }
}

pub struct Witness<'a, C: ProjectiveCurve> {
    pub secret_exponent: &'a C::ScalarField,
}

impl<'a, C: ProjectiveCurve> Witness<'a, C> {
    pub fn new(secret_exponent: &'a C::ScalarField) -> Self {
        Self { secret_exponent }
    }
}

impl<'a, C> ArgumentOfKnowledge for DLEquality<'a, C>
where
    C: ProjectiveCurve,
{
    type CommonReferenceString = Parameters<C>;
    type Statement = Statement<'a, C>;
    type Witness = Witness<'a, C>;
    type Proof = proof::Proof<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::CommonReferenceString, CryptoError> {
        let generator1 = C::rand(rng).into_affine();
        let generator2 = C::rand(rng).into_affine();
        let parameters = Parameters::<C>::new(generator1, generator2);

        Ok(parameters)
    }

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
