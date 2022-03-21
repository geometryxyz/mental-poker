use super::{Parameters, Statement};

use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::arguments::{zero_value_bilinear_map, zero_value_bilinear_map::YMapping};
use crate::zkp::{arguments::scalar_powers, transcript::TranscriptProtocol, ArgumentOfKnowledge};

use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use merlin::Transcript;

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    // Round 1
    pub b_commits: Vec<Comm::Commitment>,

    // Round 2
    pub zero_arg_proof: zero_value_bilinear_map::proof::Proof<Scalar, Comm>,
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
        let mut transcript = Transcript::new(b"hadamard_product_argument");

        // check c_b_1 = c_a_1
        if statement.commitment_to_a[0] != self.b_commits[0] {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Hadamard Product (5.1)",
            )));
        }

        // check c_b_m = c_b
        if statement.commitment_to_b != self.b_commits[proof_parameters.m - 1] {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Hadamard Product (5.1)",
            )));
        }

        // Public parameters
        transcript.append(b"commit_key", proof_parameters.commit_key);
        transcript.append(b"m", &proof_parameters.m);
        transcript.append(b"n", &proof_parameters.n);

        // Commited values
        transcript.append(b"b_commit", &self.b_commits);

        // Extract challenges
        let x: Scalar = transcript.challenge_scalar(b"x");
        let y: Scalar = transcript.challenge_scalar(b"y");

        // Precompute all powers of the x challenge from 0 to m-1
        let x_challenge_powers = scalar_powers(x, proof_parameters.m - 1);

        // Use the second challenge to define our bilinear mapping
        let prover_mapping = YMapping::new(y, proof_parameters.n);

        let mut c_d_i = self
            .b_commits
            .iter()
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(&b_i_commit, &x_power_i)| b_i_commit * x_power_i)
            .collect::<Vec<Comm::Commitment>>();

        let temp_x_c_d_shifted = self
            .b_commits
            .iter()
            .skip(1)
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(&b_i_commit, &x_power_i)| b_i_commit * x_power_i)
            .collect::<Vec<Comm::Commitment>>();

        let final_cd: Comm::Commitment = temp_x_c_d_shifted
            .iter()
            .fold(Comm::Commitment::zero(), |acc, &x| acc + x);
        c_d_i.push(final_cd);

        // Engage in zero argument
        let zero_arg_parameters = zero_value_bilinear_map::Parameters::new(
            proof_parameters.m,
            proof_parameters.n,
            proof_parameters.commit_key,
        );

        let minus_one = -Scalar::one();
        let vec_minus_ones = vec![minus_one; proof_parameters.n];
        let minus_ones_commit =
            Comm::commit(proof_parameters.commit_key, &vec_minus_ones, Scalar::zero())?;
        let vec_commits_to_a: Vec<Comm::Commitment> =
            [&statement.commitment_to_a[1..], &[minus_ones_commit]]
                .concat()
                .to_vec();

        let zero_arg_statement =
            zero_value_bilinear_map::Statement::new(&vec_commits_to_a, &c_d_i, &prover_mapping);

        match zero_value_bilinear_map::ZeroValueArgument::verify(
            &zero_arg_parameters,
            &zero_arg_statement,
            &self.zero_arg_proof,
        ) {
            Ok(_) => Ok(()),
            Err(_) => Err(CryptoError::ProofVerificationError(String::from(
                "Hadamard Product (5.1)",
            ))),
        }
    }
}
