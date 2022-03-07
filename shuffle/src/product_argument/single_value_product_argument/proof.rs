use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField};

use merlin::Transcript;
use crate::transcript::TranscriptProtocol;

use crate::utils::{HomomorphicCommitment, PedersenCommitment};
use crate::error::Error;
use crate::product_argument::single_value_product_argument::{Statement, Parameters};

pub struct Proof<C> 
where 
    C: ProjectiveCurve
{
    // round 1
    pub(crate) d_commit: C,
    pub(crate) delta_commit: C,
    pub(crate) diff_commit: C,

    // round 2
    pub(crate) a_blinded: Vec<C::ScalarField>,
    pub(crate) b_blinded: Vec<C::ScalarField>,
    pub(crate) r_blinded: C::ScalarField,
    pub(crate) s_blinded: C::ScalarField,
}

impl<C> Proof<C> 
    where
        C: ProjectiveCurve
{
    pub fn verify(&self, proof_parameters: &Parameters<C>, statement: &Statement<C>) -> Result<(), Error> {
        if self.b_blinded.len() != proof_parameters.n {
            return Err(Error::SingleValueProductVerificationError);
        }
        if self.a_blinded.len() != proof_parameters.n {
            return Err(Error::SingleValueProductVerificationError);
        }
        if self.b_blinded[0] != self.a_blinded[0] {
            return Err(Error::SingleValueProductVerificationError);
        }

        let mut transcript = Transcript::new(b"single_value_product_argument");
        //public information
        transcript.append(b"commit_key", proof_parameters.commit_key);
        transcript.append(b"a_commit", &statement.a_commit);

        //commits
        transcript.append(b"d_commit", &self.d_commit);
        transcript.append(b"delta_commit", &self.delta_commit);
        transcript.append(b"diff_commit", &self.diff_commit);

        let x: C::ScalarField = transcript.challenge_scalar(b"x");

        if self.b_blinded[proof_parameters.n - 1] != x * statement.b {
            return Err(Error::SingleValueProductVerificationError);
        }

        // verify that blinded a is correctly formed
        let left = statement.a_commit.mul(x.into_repr()) + self.d_commit;
        let right = PedersenCommitment::<C>::commit_vector(proof_parameters.commit_key, &self.a_blinded, self.r_blinded);
        if left != right {
            return Err(Error::SingleValueProductVerificationError);
        }

        //verify that diffs are correctly formed
        let left = self.diff_commit.mul(x.into_repr()) + self.delta_commit;
        let blinded_diffs = self.b_blinded.iter().skip(1)
            .zip(self.b_blinded.iter().take(self.b_blinded.len() - 1))
            .zip(self.a_blinded.iter().skip(1))
            .map(|((&b, &b_minus_one), &a)| {
                x*b - b_minus_one*a
            }).collect::<Vec<_>>();

        let right = PedersenCommitment::<C>::commit_vector(proof_parameters.commit_key, &blinded_diffs, self.s_blinded);
        if left != right {
            return Err(Error::SingleValueProductVerificationError)
        }

        Ok(())
    }
}