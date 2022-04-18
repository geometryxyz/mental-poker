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

#[derive(Copy, Clone)]
pub struct Parameters<'a, C: ProjectiveCurve> {
    pub g: &'a C::Affine,
    pub h: &'a C::Affine,
}

impl<'a, C: ProjectiveCurve> Parameters<'a, C> {
    pub fn new(g: &'a C::Affine, h: &'a C::Affine) -> Self {
        Self { g, h }
    }
}

/// Statement for a Chaum-Pedersen proof of discrete logarithm equality.
/// Expects two points $A$ and $B$ such that for some secret $x$ and parameters
/// $G$ and $H$, $A = xG$ and $B=xH$
#[derive(Copy, Clone)]
pub struct Statement<'a, C: ProjectiveCurve>(pub &'a C::Affine, pub &'a C::Affine);

impl<'a, C: ProjectiveCurve> Statement<'a, C> {
    pub fn new(point_a: &'a C::Affine, point_b: &'a C::Affine) -> Self {
        Self(point_a, point_b)
    }
}

type Witness<C> = <C as ProjectiveCurve>::ScalarField;

impl<'a, C> ArgumentOfKnowledge for DLEquality<'a, C>
where
    C: ProjectiveCurve,
{
    type CommonReferenceString = Parameters<'a, C>;
    type Statement = Statement<'a, C>;
    type Witness = Witness<C>;
    type Proof = proof::Proof<C>;

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
