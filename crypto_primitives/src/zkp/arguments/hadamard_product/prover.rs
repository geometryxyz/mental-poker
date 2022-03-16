use super::{proof::Proof, Parameters, Statement, Witness};

use crate::error::CryptoError;
use crate::utils::rand::sample_vector;
use crate::utils::vector_arithmetic::{dot_product, hadamard_product};
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::arguments::{zero_value_bilinear_map, zero_value_bilinear_map::YMapping};
use crate::zkp::{transcript::TranscriptProtocol, ArgumentOfKnowledge};

use ark_ff::{Field, Zero};
use merlin::Transcript;
use rand::Rng;
use std::iter;

pub struct Prover<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    parameters: &'a Parameters<'a, Scalar, Comm>,
    transcript: Transcript,
    statement: &'a Statement<'a, Scalar, Comm>,
    witness: &'a Witness<'a, Scalar>,
}

impl<'a, Scalar, Comm> Prover<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(
        parameters: &'a Parameters<'a, Scalar, Comm>,
        statement: &'a Statement<'a, Scalar, Comm>,
        witness: &'a Witness<'a, Scalar>,
    ) -> Self {
        Self {
            parameters,
            transcript: Transcript::new(b"hadamard_product_argument"),
            statement,
            witness,
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) -> Result<Proof<Scalar, Comm>, CryptoError> {
        let mut transcript = self.transcript.clone();

        // Compute intermediate products (b values). Final b should be the one from the witness
        let mut acc = vec![Scalar::one(); self.parameters.n];

        let b = self.witness.matrix_a[..self.witness.matrix_a.len() - 1]
            .iter()
            .map(|x| {
                acc = acc
                    .iter()
                    .zip(x.iter())
                    .map(|(&s_a, &s_b)| s_a * s_b)
                    .collect();
                acc.clone()
            })
            .chain(iter::once(self.witness.vector_b.to_vec()))
            .collect::<Vec<_>>();

        let mut s: Vec<Scalar> = sample_vector(rng, self.parameters.m - 2);

        let b_commit_middle = b
            .iter()
            .take(b.len() - 1)
            .skip(1)
            .zip(s.iter())
            .map(|(b_i, &s_i)| -> Result<Comm::Commitment, CryptoError> {
                Comm::commit(self.parameters.commit_key, b_i, s_i)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let b_commit = iter::once(self.statement.commitment_to_a[0])
            .chain(b_commit_middle.into_iter())
            .chain(iter::once(self.statement.commitment_to_b))
            .collect::<Vec<Comm::Commitment>>();

        s.insert(0, self.witness.randoms_for_a_commit[0]);
        s.push(self.witness.random_for_b_commit);

        // Public parameters
        transcript.append(b"commit_key", self.parameters.commit_key);
        transcript.append(b"m", &self.parameters.m);
        transcript.append(b"n", &self.parameters.n);

        // Commited values
        transcript.append(b"b_commit", &b_commit);

        // Challenges
        let x = transcript.challenge_scalar(b"x");
        let y = transcript.challenge_scalar(b"y");

        // Precompute all powers of the x challenge
        let x_challenge_powers = iter::once(Scalar::one())
            .chain(iter::once(x))
            .chain((1..self.parameters.m - 1).scan(x, |current_power, _exp| {
                *current_power *= x;
                Some(*current_power)
            }))
            .collect::<Vec<_>>();

        // Use the second challenge to define our bilinear mapping
        let prover_mapping = YMapping::new(y, self.parameters.n);

        // Prepare statement
        let minus_one = -Scalar::one();
        let vec_minus_ones = vec![minus_one; self.parameters.n];
        let minus_ones_commit =
            Comm::commit(self.parameters.commit_key, &vec_minus_ones, Scalar::zero())?;

        let vec_commits_to_a: Vec<Comm::Commitment> =
            [&self.statement.commitment_to_a[..], &[minus_ones_commit]]
                .concat()
                .to_vec();

        let mut c_d_i = b_commit
            .iter()
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(&b_i_commit, &x_power_i)| b_i_commit * x_power_i)
            .collect::<Vec<_>>();

        let temp_x_c_d_shifted = b_commit
            .iter()
            .skip(1)
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(&b_i_commit, &x_power_i)| b_i_commit * x_power_i)
            .collect::<Vec<_>>();

        let final_cd = temp_x_c_d_shifted
            .iter()
            .fold(Comm::Commitment::zero(), |acc, &x| acc + x);
        c_d_i.push(final_cd);

        // prepare witness
        let vec_openings_to_a = [&self.witness.matrix_a[1..], &[vec_minus_ones]]
            .concat()
            .to_vec();
        let vec_randoms_for_a = [&self.witness.randoms_for_a_commit[1..], &[Scalar::zero()]]
            .concat()
            .to_vec();

        let final_t = dot_product(
            &x_challenge_powers[1..=self.parameters.m - 1].to_vec(),
            &s[1..=self.parameters.m - 1].to_vec(),
        )?;

        let vec_randoms_for_d = x_challenge_powers
            .iter()
            .skip(1)
            .zip(s.iter())
            .map(|(&x_power_i, &s_i)| x_power_i * s_i)
            .chain(iter::once(final_t))
            .collect::<Vec<Scalar>>();

        let temp_x_b = b[1..=self.parameters.m - 1]
            .to_vec()
            .iter()
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(b_chunk, &x_power_i)| {
                let x_power_i_vector = vec![x_power_i; self.parameters.n];
                hadamard_product(b_chunk, &x_power_i_vector)
            })
            .collect::<Result<Vec<Vec<Scalar>>, CryptoError>>()?;

        let final_d = temp_x_b
            .into_iter()
            .reduce(|x, y| {
                x.iter()
                    .zip(y.iter())
                    .map(|(&s_a, &s_b)| s_a + s_b)
                    .collect()
            })
            .unwrap();

        let vec_openings_to_d = b
            .iter()
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(b_chunk, &x_power_i)| {
                let x_power_i_vector = vec![x_power_i; self.parameters.n];
                hadamard_product(b_chunk, &x_power_i_vector)
            })
            .collect::<Result<Vec<_>, CryptoError>>()?
            .into_iter()
            .chain(iter::once(final_d))
            .collect::<Vec<_>>();

        let vec_commits_to_a_shifted = vec_commits_to_a[1..].to_vec();
        let zero_arg_statement = zero_value_bilinear_map::Statement::new(
            &vec_commits_to_a_shifted,
            &c_d_i,
            &prover_mapping,
        );

        let zero_arg_params = zero_value_bilinear_map::Parameters::new(
            self.parameters.m,
            self.parameters.n,
            self.parameters.commit_key,
        );

        let zero_arg_witness = zero_value_bilinear_map::Witness::new(
            &vec_openings_to_a,
            &vec_randoms_for_a,
            &vec_openings_to_d,
            &vec_randoms_for_d,
        );

        let zero_arg_proof = zero_value_bilinear_map::ZeroValueArgument::prove(
            rng,
            &zero_arg_params,
            &zero_arg_statement,
            &zero_arg_witness,
        )?;

        let proof = Proof {
            // Round 1
            b_commits: b_commit,

            // Round 2
            zero_arg_proof: zero_arg_proof,
        };

        Ok(proof)
    }
}
