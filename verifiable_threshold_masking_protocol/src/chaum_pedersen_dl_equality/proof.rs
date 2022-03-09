use crate::chaum_pedersen_dl_equality::{error::Error, transcript::TranscriptProtocol, Parameters};
use crate::discrete_log_vtmp::ElgamalCipher;

use ark_ec::{AffineCurve, ProjectiveCurve};
use merlin::Transcript;

pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub(crate) a: C,
    pub(crate) b: C,
    pub(crate) r: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify(
        &self,
        parameters: &Parameters<C>,
        statement: &ElgamalCipher<C>,
    ) -> Result<(), Error> {
        let mut transcript = Transcript::new(b"chaum_pedersen");

        transcript.append(b"g", &parameters.g);
        transcript.append(b"h", &parameters.h);
        transcript.append(b"x", &statement.0);
        transcript.append(b"y", &statement.1);

        transcript.append(b"a", &self.a);
        transcript.append(b"b", &self.b);

        let c: C::ScalarField = transcript.challenge_scalar(b"c");

        // g * r ==? a + x*c
        if parameters.g.mul(self.r) != self.a + statement.0.mul(c) {
            return Err(Error::VerificationError);
        }

        // h * r ==? b + y*c
        if parameters.h.mul(self.r) != self.b + statement.1.mul(c) {
            return Err(Error::VerificationError);
        }

        Ok(())
    }
}
