use super::{proof::Proof, BilinearMap, Parameters, Statement, Witness};

use crate::error::CryptoError;
use crate::utils::{rand::sample_vector, vector_arithmetic::dot_product};
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::arguments::scalar_powers;
use ark_ff::Field;
use merlin::Transcript;

use crate::zkp::transcript::TranscriptProtocol;
use rand::Rng;

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
            transcript: Transcript::new(b"zero_argument"),
            statement,
            witness,
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) -> Result<Proof<Scalar, Comm>, CryptoError> {
        let mut transcript = self.transcript.clone();

        let a_0: Vec<Scalar> = sample_vector(rng, self.parameters.n);
        let b_m: Vec<Scalar> = sample_vector(rng, self.parameters.n);

        let r_0 = Scalar::rand(rng);
        let s_m = Scalar::rand(rng);

        let a_0_commit = Comm::commit(self.parameters.commit_key, &a_0, r_0)?;
        let b_m_commit = Comm::commit(self.parameters.commit_key, &b_m, s_m)?;

        let a_0_vec = vec![a_0.clone(); 1];
        let extended_a = [&a_0_vec[..], &self.witness.matrix_a[..]].concat();

        let b_m_vec = vec![b_m.clone(); 1];
        let extended_b = [&self.witness.matrix_b[..], &b_m_vec[..]].concat();

        let diagonals = self
            .diagonals_from_chunks(
                &extended_a,
                &extended_b,
                self.parameters.m + 1,
                Scalar::zero(),
            )
            .unwrap();

        let mut t: Vec<Scalar> = sample_vector(rng, 2 * self.parameters.m + 1);
        t[self.parameters.m + 1] = Scalar::zero();

        let vector_of_commited_diagonals = diagonals
            .iter()
            .zip(t.iter())
            .map(|(&diagonal, &random)| -> Result<_, CryptoError> {
                Comm::commit(self.parameters.commit_key, &vec![diagonal], random)
            })
            .collect::<Result<Vec<_>, CryptoError>>()?;

        // Public parameters
        transcript.append(b"commit_key", self.parameters.commit_key);
        transcript.append(b"m", &self.parameters.m);
        transcript.append(b"n", &self.parameters.n);

        // Random values
        transcript.append(b"c_a_0", &a_0_commit);
        transcript.append(b"c_b_m", &b_m_commit);

        // Commitments
        transcript.append(b"commitment_to_a", self.statement.commitment_to_a);
        transcript.append(b"commitment_to_b", self.statement.commitment_to_b);
        transcript.append(
            b"vector_of_commited_diagonals",
            &vector_of_commited_diagonals,
        );

        let x: Scalar = transcript.challenge_scalar(b"x");

        // Precompute all powers of the challenge from 0 to number_of_diagonals of the extended matrix
        let challenge_powers = scalar_powers(x, 2 * self.parameters.m);

        let first_m_powers = challenge_powers[0..self.parameters.m].to_vec();
        let mut first_m_powers_reversed = first_m_powers[..].to_vec();
        first_m_powers_reversed.reverse();

        let first_m_non_zero_powers = challenge_powers[1..self.parameters.m + 1].to_vec();
        let mut first_m_non_zero_powers_reversed = first_m_non_zero_powers[..].to_vec();
        first_m_non_zero_powers_reversed.reverse();

        // a1[0]x + a2[0]x^2 ... am[0]x^m
        // a1[1]x + a2[1]x^2 ... am[1]x^m
        // a1[2]x + a2[2]x^2 ... am[2]x^m
        // a1[3]x + a2[3]x^2 ... am[3]x^m
        // ...
        // a1[n]x + a2[n]x^2 ... am[n]x^m = b[n]
        let mut a_blinded: Vec<Scalar> = Vec::with_capacity(self.parameters.m + 1);
        for i in 0..self.parameters.n {
            let mut poly = a_0[i];
            for j in 0..self.parameters.m {
                poly = poly + self.witness.matrix_a[j][i] * first_m_non_zero_powers[j];
            }
            a_blinded.push(poly);
        }

        let mut b_blinded: Vec<Scalar> = Vec::with_capacity(self.parameters.m + 1);
        for i in 0..self.parameters.n {
            let mut poly = b_m[i];
            for j in 0..self.parameters.m {
                poly = poly + self.witness.matrix_b[j][i] * first_m_non_zero_powers_reversed[j];
            }
            b_blinded.push(poly);
        }

        let r_blinded =
            r_0 + dot_product(&self.witness.randoms_for_a_commit, &first_m_non_zero_powers)?;
        let s_blinded = dot_product(
            &self.witness.randoms_for_b_commit,
            &first_m_non_zero_powers_reversed,
        )? + s_m;
        let t_blinded = dot_product(&t, &challenge_powers)?;

        let proof = Proof {
            a_0_commit,
            b_m_commit,
            vector_of_commited_diagonals,

            a_blinded,
            b_blinded,
            r_blinded,
            s_blinded,
            t_blinded,
        };

        Ok(proof)
    }

    fn diagonals_from_chunks(
        &self,
        a_chunks: &Vec<Vec<Scalar>>,
        b_chunks: &Vec<Vec<Scalar>>,
        statement_diagonal: usize,
        statement_value: Scalar,
    ) -> Result<Vec<Scalar>, CryptoError> {
        if a_chunks.len() != b_chunks.len() {
            return Err(CryptoError::DiagonalLengthError(
                a_chunks.len(),
                b_chunks.len(),
            ));
        }

        let m = a_chunks.len();
        let num_of_diagonals = 2 * m - 1;

        let mut diagonal_sums = vec![Scalar::zero(); num_of_diagonals];
        let center = num_of_diagonals / 2 as usize;

        for d in 1..m {
            let mut tmp_product1 = Scalar::zero();
            let mut tmp_product2 = Scalar::zero();
            for i in d..m {
                let dot = self
                    .statement
                    .bilinear_map
                    .compute_mapping(&a_chunks[i - d], &b_chunks[i])
                    .unwrap();
                tmp_product1 = tmp_product1 + dot;

                let dot = self
                    .statement
                    .bilinear_map
                    .compute_mapping(&a_chunks[i], &b_chunks[i - d])
                    .unwrap();
                tmp_product2 = tmp_product2 + dot;
            }

            diagonal_sums[center - d] = tmp_product1;
            diagonal_sums[center + d] = tmp_product2;
        }

        let product: Scalar = a_chunks
            .iter()
            .zip(b_chunks.iter())
            .map(|(a_i, b_i)| {
                self.statement
                    .bilinear_map
                    .compute_mapping(a_i, b_i)
                    .unwrap()
            })
            .sum();

        diagonal_sums[center] = product;
        diagonal_sums[statement_diagonal] = statement_value;

        Ok(diagonal_sums)
    }
}
