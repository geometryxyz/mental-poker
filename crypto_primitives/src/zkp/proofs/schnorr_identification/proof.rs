use crate::zkp::transcript::TranscriptProtocol;
use ark_ff::PrimeField;

use super::{Parameters, Statement};
use crate::error::Error;
use ark_ec::{AffineCurve, ProjectiveCurve};
use merlin::Transcript;

pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub(crate) random_commit: C,
    pub(crate) opening: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify(&self, pp: &Parameters<C>, statement: &Statement<C>) -> Result<(), Error> {
        let mut transcript = Transcript::new(b"schnorr_identity");

        transcript.append(b"public_generator", &pp.generator);
        transcript.append(b"public_key", statement.statement);
        transcript.append(b"witness_commit", &self.random_commit);

        let c: C::ScalarField = transcript.challenge_scalar(b"c");

        if pp.generator.mul(self.opening.into_repr()) + statement.statement.mul(c.into_repr())
            != self.random_commit
        {
            return Err(Error::VerificationError);
        }

        Ok(())
    }
}
