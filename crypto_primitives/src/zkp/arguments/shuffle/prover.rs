use super::{proof::Proof, Parameters, Statement, Witness};

use crate::zkp::arguments::{matrix_elements_product as product_argument, multi_exponentiation};
use ark_ff::{Field, Zero};

use crate::error::CryptoError;
use crate::homomorphic_encryption::HomomorphicEncryptionScheme;
use crate::utils::rand::sample_vector;
use crate::utils::vector_arithmetic::{dot_product, reshape};
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::arguments::scalar_powers;
use crate::zkp::transcript::TranscriptProtocol;
use crate::zkp::ArgumentOfKnowledge;

use merlin::Transcript;
use rand::Rng;

pub struct Prover<'a, Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    parameters: &'a Parameters<'a, Scalar, Enc, Comm>,
    transcript: Transcript,
    statement: &'a Statement<'a, Scalar, Enc>,
    witness: &'a Witness<'a, Scalar>,
}

impl<'a, Scalar, Enc, Comm> Prover<'a, Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(
        parameters: &'a Parameters<'a, Scalar, Enc, Comm>,
        statement: &'a Statement<'a, Scalar, Enc>,
        witness: &'a Witness<'a, Scalar>,
    ) -> Self {
        //TODO add dimension assertions
        Self {
            parameters,
            transcript: Transcript::new(b"shuffle_argument"),
            statement,
            witness,
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) -> Result<Proof<Scalar, Enc, Comm>, CryptoError> {
        let mut transcript = self.transcript.clone();

        let r: Vec<Scalar> = sample_vector(rng, self.statement.m);

        let index = (1..=self.statement.m * self.statement.n)
            .map(|x| Scalar::from(x as u64))
            .collect::<Vec<_>>();

        let a = self.witness.permutation.permute_array(&index);

        let a_chunks = reshape(&a, self.statement.m, self.statement.n)?;

        let a_commits = a_chunks
            .iter()
            .zip(r.iter())
            .map(|(chunk, &r)| Comm::commit(self.parameters.commit_key, chunk, r))
            .collect::<Result<Vec<_>, CryptoError>>()?;

        // Public data
        transcript.append(b"public_key", self.parameters.public_key);
        transcript.append(b"commit_key", self.parameters.commit_key);

        // statement
        transcript.append(b"ciphers", self.statement.input_ciphers);
        transcript.append(b"shuffled", self.statement.shuffled_ciphers);
        transcript.append(b"m", &self.statement.m);
        transcript.append(b"n", &self.statement.n);

        // round 1
        transcript.append(b"a_commits", &a_commits);

        let x: Scalar = transcript.challenge_scalar(b"x");

        let challenge_powers = scalar_powers(x, self.witness.permutation.size)[1..].to_vec();
        println!("prover {}", challenge_powers.len());

        let b = self.witness.permutation.permute_array(&challenge_powers);
        let s: Vec<Scalar> = sample_vector(rng, self.statement.m);

        let b_chunks = b
            .chunks(self.statement.n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let b_commits = b_chunks
            .iter()
            .zip(s.iter())
            .map(|(b, &s)| Comm::commit(self.parameters.commit_key, b, s))
            .collect::<Result<Vec<_>, CryptoError>>()?;

        //round 2
        transcript.append(b"b_commits", &b_commits);

        let y: Scalar = transcript.challenge_scalar(b"y");
        let z: Scalar = transcript.challenge_scalar(b"z");

        let d = a
            .iter()
            .zip(b.iter())
            .map(|(&a, &b)| y * a + b)
            .collect::<Vec<_>>();
        let t = r
            .iter()
            .zip(s.iter())
            .map(|(&r, &s)| y * r + s)
            .collect::<Vec<_>>();

        // Engage in product argument ---------------------------------------------------------------------
        let product_argument_parameters = product_argument::Parameters::new(
            self.statement.m,
            self.statement.n,
            self.parameters.commit_key,
        );

        let d_minus_z = d.iter().map(|&x| x - z).collect::<Vec<Scalar>>();
        let d_minus_z_chunks = d_minus_z
            .chunks(self.statement.n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let d_minus_z_commits = d_minus_z_chunks
            .iter()
            .zip(t.iter())
            .map(|(chunk, &random)| Comm::commit(self.parameters.commit_key, chunk, random))
            .collect::<Result<Vec<_>, CryptoError>>()?;

        let claimed_product = d_minus_z.iter().product();

        let product_argument_statement =
            product_argument::Statement::new(&d_minus_z_commits, claimed_product);

        let product_argument_witness = product_argument::Witness::new(&d_minus_z_chunks, &t);

        let product_argument_prover = product_argument::prover::Prover::new(
            &product_argument_parameters,
            &product_argument_statement,
            &product_argument_witness,
        );

        let product_argument_proof = product_argument_prover.prove(rng)?;

        // Engage in multi-exponentation argument ----------------------------------------------------------
        let multi_exp_parameters = multi_exponentiation::Parameters::new(
            self.parameters.encrypt_parameters,
            self.parameters.public_key,
            self.parameters.commit_key,
            self.parameters.generator,
        );

        let minus_rho_witness = self.witness.rho.iter().map(|&x| -x).collect::<Vec<_>>();
        let rho = dot_product(&minus_rho_witness, &b)?;

        let temp = dot_product(&b, self.statement.shuffled_ciphers)?;
        let zero_cipher = Enc::Plaintext::zero();
        let masking_cipher = Enc::encrypt(
            self.parameters.encrypt_parameters,
            self.parameters.public_key,
            &zero_cipher,
            &rho,
        )?;

        let product = temp + masking_cipher;

        let shuffled_chunks = self
            .statement
            .shuffled_ciphers
            .chunks(self.statement.n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let multi_exp_statement =
            multi_exponentiation::Statement::new(&shuffled_chunks, product, &b_commits);

        let multi_exp_witness = multi_exponentiation::Witness::new(&b_chunks, &s, rho);

        let multi_exp_proof = multi_exponentiation::MultiExponentiation::prove(
            rng,
            &multi_exp_parameters,
            &multi_exp_statement,
            &multi_exp_witness,
        )?;

        // Produce proof
        let proof = Proof {
            a_commits,
            b_commits,
            product_argument_proof,
            multi_exp_proof,
        };

        Ok(proof)
    }
}
