use super::{Parameters, Statement};

use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::transcript::TranscriptProtocol;

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use merlin::Transcript;

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    // round 1
    pub(crate) d_commit: Comm::Commitment,
    pub(crate) delta_commit: Comm::Commitment,
    pub(crate) diff_commit: Comm::Commitment,

    // round 2
    pub(crate) a_blinded: Vec<Scalar>,
    pub(crate) b_blinded: Vec<Scalar>,
    pub(crate) r_blinded: Scalar,
    pub(crate) s_blinded: Scalar,
}

impl<Scalar, Comm> Proof<Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn verify(
        &self,
        proof_parameters: &Parameters<Scalar, Comm>,
        statement: &Statement<Scalar, Comm>,
    ) -> Result<(), CryptoError> {
        if self.b_blinded.len() != proof_parameters.n {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Single Value Product Argument (5.3)",
            )));
        }
        if self.a_blinded.len() != proof_parameters.n {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Single Value Product Argument (5.3)",
            )));
        }
        if self.b_blinded[0] != self.a_blinded[0] {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Single Value Product Argument (5.3)",
            )));
        }

        let mut transcript = Transcript::new(b"single_value_product_argument");
        //public information
        transcript.append(b"commit_key", proof_parameters.commit_key);
        transcript.append(b"a_commit", statement.a_commit);

        //commits
        transcript.append(b"d_commit", &self.d_commit);
        transcript.append(b"delta_commit", &self.delta_commit);
        transcript.append(b"diff_commit", &self.diff_commit);

        let x: Scalar = transcript.challenge_scalar(b"x");

        if self.b_blinded[proof_parameters.n - 1] != x * statement.b {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Single Value Product Argument (5.3)",
            )));
        }

        // verify that blinded a is correctly formed
        // let left = statement.a_commit.mul(x.into_repr()) + self.d_commit;
        let left = *statement.a_commit * x + self.d_commit;
        let right = Comm::commit(proof_parameters.commit_key, &self.a_blinded, self.r_blinded)?;
        if left != right {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Single Value Product Argument (5.3)",
            )));
        }

        //verify that diffs are correctly formed
        // let left = self.diff_commit.mul(x.into_repr()) + self.delta_commit;
        let left = self.diff_commit * x + self.delta_commit;
        let blinded_diffs = self
            .b_blinded
            .iter()
            .skip(1)
            .zip(self.b_blinded.iter().take(self.b_blinded.len() - 1))
            .zip(self.a_blinded.iter().skip(1))
            .map(|((&b, &b_minus_one), &a)| x * b - b_minus_one * a)
            .collect::<Vec<_>>();

        let right = Comm::commit(proof_parameters.commit_key, &blinded_diffs, self.s_blinded)?;
        if left != right {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Single Value Product Argument (5.3)",
            )));
        }

        Ok(())
    }
}
