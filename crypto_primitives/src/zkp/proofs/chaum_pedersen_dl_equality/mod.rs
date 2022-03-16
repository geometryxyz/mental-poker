pub mod proof;
pub mod prover;
mod test;

use crate::error::CryptoError;
use crate::zkp::ArgumentOfKnowledge;
use ark_ec::ProjectiveCurve;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

pub struct DLEquality<C: ProjectiveCurve> {
    _group: PhantomData<C>,
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

/// Statement for a Chaum-Pedersen proof of discrete logarithm equality.
/// Expects two points $A$ and $B$ such that for some secret $x$ and parameters
/// $G$ and $H$, $A = xG$ and $B=xH$
pub struct Statement<C: ProjectiveCurve>(pub C::Affine, pub C::Affine);

impl<'a, C: ProjectiveCurve> Statement<C> {
    pub fn new(point_a: C::Affine, point_b: C::Affine) -> Self {
        Self(point_a, point_b)
    }
}

type Witness<C> = <C as ProjectiveCurve>::ScalarField;

impl<C> ArgumentOfKnowledge for DLEquality<C>
where
    C: ProjectiveCurve,
{
    type CommonReferenceString = Parameters<C>;
    type Statement = Statement<C>;
    type Witness = Witness<C>;
    type Proof = proof::Proof<C>;

    // fn setup<R: Rng>(rng: &mut R) -> Result<Self::CommonReferenceString, CryptoError> {
    //     let generator1 = C::rand(rng).into_affine();
    //     let generator2 = C::rand(rng).into_affine();
    //     let parameters = Parameters::<C>::new(generator1, generator2);

    //     Ok(parameters)
    // }

    fn prove<R: Rng>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, CryptoError> {
        Ok(prover::Prover::create_proof(
            rng,
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
