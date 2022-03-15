use super::{Parameters, Statement};

use crate::error::CryptoError;
use crate::zkp::transcript::TranscriptProtocol;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use merlin::Transcript;

#[derive(Copy, Clone)]
pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub(crate) random_commit: C,
    pub(crate) opening: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify(&self, pp: &Parameters<C>, statement: &Statement<C>) -> Result<(), CryptoError> {
        let mut transcript = Transcript::new(b"schnorr_identity");

        transcript.append(b"public_generator", pp);
        transcript.append(b"public_key", statement);
        transcript.append(b"witness_commit", &self.random_commit);

        let c: C::ScalarField = transcript.challenge_scalar(b"c");

        if pp.mul(self.opening.into_repr()) + statement.mul(c.into_repr()) != self.random_commit {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification",
            )));
        }

        Ok(())
    }
}
