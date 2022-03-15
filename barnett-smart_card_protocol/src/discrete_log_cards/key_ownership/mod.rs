use super::{PlayerSecretKey, ProofKeyOwnership, PublicKey};
use crate::Verifiable;
use ark_ec::ProjectiveCurve;
use ark_std::marker::PhantomData;
use crypto_primitives::error::CryptoError;
use crypto_primitives::zkp::proofs::schnorr_identification;
use crypto_primitives::zkp::ArgumentOfKnowledge;

/// Wrapper type around a Schnorr Identification scheme to work with types from our card protocol.
pub struct KeyOwnershipArg<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

impl<C: ProjectiveCurve> ArgumentOfKnowledge for KeyOwnershipArg<C> {
    type CommonReferenceString = C::Affine;
    type Statement = PublicKey<C>;
    type Witness = PlayerSecretKey<C>;
    type Proof = ProofKeyOwnership<C>;

    fn prove(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, CryptoError> {
        let proof = schnorr_identification::SchnorrIdentification::prove(
            common_reference_string,
            statement,
            witness,
        )?;

        Ok(proof)
    }

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
    ) -> Result<(), CryptoError> {
        schnorr_identification::SchnorrIdentification::verify(
            common_reference_string,
            statement,
            proof,
        )
    }
}

impl<C: ProjectiveCurve> Verifiable<KeyOwnershipArg<C>> for ProofKeyOwnership<C> {
    fn verify_proof(
        &self,
        parameters: &C::Affine,
        statement: &PublicKey<C>,
    ) -> Result<(), CryptoError> {
        KeyOwnershipArg::verify(parameters, statement, self)
    }
}
