use super::proof::Proof;
use super::{Parameters, Statement, Witness};

use crate::error::CryptoError;
use crate::homomorphic_encryption::HomomorphicEncryptionScheme;
use crate::utils::{rand::sample_vector, vector_arithmetic::dot_product};
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::{arguments::scalar_powers, transcript::TranscriptProtocol};

use ark_ff::{Field, Zero};
use ark_std::rand::thread_rng;
use merlin::Transcript;
use std::marker::PhantomData;

pub struct Prover<'a, Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    parameters: &'a Parameters<'a, Scalar, Enc, Comm>,
    transcript: Transcript,
    statement: &'a Statement<'a, Scalar, Enc, Comm>,
    witness: &'a Witness<'a, Scalar>,
    _encryption_scheme: PhantomData<Enc>,
    _commitment_scheme: PhantomData<Comm>,
}

impl<'a, Scalar, Enc, Comm> Prover<'a, Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(
        parameters: &'a Parameters<'a, Scalar, Enc, Comm>,
        statement: &'a Statement<'a, Scalar, Enc, Comm>,
        witness: &'a Witness<'a, Scalar>,
    ) -> Self {
        //TODO add dimension assertions
        Self {
            parameters,
            transcript: Transcript::new(b"multi_exponent_argument"),
            statement,
            witness,
            _encryption_scheme: PhantomData::<Enc>,
            _commitment_scheme: PhantomData::<Comm>,
        }
    }

    pub fn prove(&self) -> Result<Proof<Scalar, Enc, Comm>, CryptoError> {
        let mut transcript = self.transcript.clone();
        let rng = &mut thread_rng();

        transcript.append(b"public_key", self.parameters.public_key);
        transcript.append(b"commit_key", self.parameters.commit_key);

        transcript.append(
            b"commitments_to_exponents",
            self.statement.commitments_to_exponents,
        );
        transcript.append(b"product", &self.statement.product);
        transcript.append(b"shuffled_ciphers", self.statement.shuffled_ciphers);

        let m = self.witness.matrix_a.len();
        let n = self.witness.matrix_a[0].len();
        let num_of_diagonals = 2 * m - 1;

        transcript.append(b"m", &m);
        transcript.append(b"n", &n);
        transcript.append(b"num_of_diagonals", &num_of_diagonals);

        let a_0: Vec<Scalar> = sample_vector(rng, n);
        let r_0 = Scalar::rand(rng);

        let mut b: Vec<Scalar> = sample_vector(rng, num_of_diagonals + 1);
        let mut s: Vec<Scalar> = sample_vector(rng, num_of_diagonals + 1);
        let mut tau: Vec<Scalar> = sample_vector(rng, num_of_diagonals + 1);

        b[m] = Scalar::zero();
        s[m] = Scalar::zero();
        tau[m] = self.witness.rho;

        let a_0_commit = Comm::commit(&self.parameters.commit_key, &a_0, r_0)?;

        let commit_b_k = b
            .iter()
            .zip(s.iter())
            .map(|(&b_k, &s_k)| {
                let commit = Comm::commit(self.parameters.commit_key, &vec![b_k], s_k)?;
                Ok(commit)
            })
            .collect::<Result<Vec<Comm::Commitment>, _>>()?;

        let diagonals = Self::diagonals_from_chunks(
            &self.statement.shuffled_ciphers,
            &self.witness.matrix_a,
            &a_0,
        )
        .unwrap();

        let vector_e_k = b
            .iter()
            .zip(tau.iter())
            .zip(diagonals.iter())
            .map(|((&b_k, tau_k), &d_k)| {
                let message = self.parameters.generator * b_k;

                let encrypted_random = Enc::encrypt(
                    &self.parameters.encrypt_parameters,
                    self.parameters.public_key,
                    &message,
                    tau_k,
                );

                // let encrypted_random = DiscreteLogVTMF::<C>::mask(
                //     encryption_parameters,
                //     self.parameters.public_key,
                //     &self.parameters.masking_generator.mul(*b_k).into_affine(),
                //     &Randomness::<C>(*tau_k),
                // );
                encrypted_random.unwrap() + d_k
            })
            .collect::<Vec<Enc::Ciphertext>>();

        transcript.append(b"a_0_commit", &a_0_commit);
        transcript.append(b"commit_B_k", &commit_b_k);
        transcript.append(b"vector_E_k", &vector_e_k);

        let challenge = transcript.challenge_scalar(b"x");

        // Precompute all powers of the challenge from 0 to number_of_diagonals
        let challenge_powers = scalar_powers(challenge, num_of_diagonals);

        // take vector x: x, x^2, x^3, ..., x^m
        let x_array = challenge_powers[1..m + 1].to_vec();

        let scalar_products_ax = self
            .witness
            .matrix_a
            .iter()
            .enumerate()
            .map(|(i, chunk)| {
                chunk
                    .iter()
                    .map(|scalar| x_array[i] * scalar)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<Vec<Scalar>>>();

        let mut a_blinded: Vec<Scalar> = Vec::with_capacity(n);

        // c0[0]x + c1[0]x^2 ... cm[0]x^m = b[0]
        // c0[1]x + c1[1]x^2 ... cm[1]x^m = b[1]
        // c0[2]x + c1[2]x^2 ... cm[2]x^m
        // c0[3]x + c1[3]x^2 ... cm[3]x^m
        // ...
        // c0[n]x + c1[n]x^2 ... cm[n]x^m = b[n]
        for i in 0..n {
            let mut poly = a_0[i];
            for j in 0..m {
                poly = poly + scalar_products_ax[j][i];
            }
            a_blinded.push(poly);
        }

        let r_blinded = r_0 + dot_product(&self.witness.matrix_blinders, &x_array)?;
        let b_blinded = dot_product(&b, &challenge_powers)?;
        let s_blinded = dot_product(&s, &challenge_powers)?;
        let tau_blinded = dot_product(&tau, &challenge_powers)?;

        let proof = Proof {
            // Round 1
            a_0_commit,
            commit_b_k,
            vector_e_k,

            // Round 2
            r_blinded,
            b_blinded,
            s_blinded,
            tau_blinded,
            a_blinded,
        };

        Ok(proof)
    }

    fn diagonals_from_chunks(
        cipher_chunks: &Vec<Vec<Enc::Ciphertext>>,
        scalar_chunks: &Vec<Vec<Scalar>>,
        a_0_randomness: &Vec<Scalar>,
    ) -> Result<Vec<Enc::Ciphertext>, CryptoError> {
        let m = cipher_chunks.len();
        let num_of_diagonals = 2 * m - 1;

        let mut diagonal_sums: Vec<Enc::Ciphertext> =
            vec![Enc::Ciphertext::zero(); num_of_diagonals];
        let center = num_of_diagonals / 2 as usize;

        for d in 1..m {
            let additional_randomness = dot_product(&a_0_randomness, &cipher_chunks[d - 1])?;
            let mut tmp_product1 = Enc::Ciphertext::zero();
            let mut tmp_product2 = Enc::Ciphertext::zero();
            for i in d..m {
                let dot = dot_product(&scalar_chunks[i - d], &cipher_chunks[i])?;
                tmp_product1 = tmp_product1 + dot;

                let dot = dot_product(&scalar_chunks[i], &cipher_chunks[i - d])?;
                tmp_product2 = tmp_product2 + dot;
            }

            diagonal_sums[center - d] = tmp_product1 + additional_randomness;
            diagonal_sums[center + d] = tmp_product2;
        }

        // let commit_b_k: Vec<_> = b
        // .iter()
        // .zip(s.iter())
        // .map(|(&b_k, &s_k)| {
        //     let commit = Comm::commit(self.parameters.commit_key, vec![b_k], s_k)?;
        //     Ok(commit)
        // }).collect()?;

        let product: Result<Vec<Enc::Ciphertext>, CryptoError> = cipher_chunks
            .iter()
            .zip(scalar_chunks.iter())
            .map(|(c_i, a_i)| {
                let dot_p = dot_product(a_i, c_i)?;
                Ok(dot_p)
            })
            .collect();

        let product = product?
            .iter()
            .fold(Enc::Ciphertext::zero(), |acc, &x| acc + x);
        // .sum();

        diagonal_sums[center] = product;

        let zeroth_diagonal = dot_product(&a_0_randomness, &cipher_chunks.last().unwrap())?;
        diagonal_sums.insert(0, zeroth_diagonal);

        Ok(diagonal_sums)
    }
}
