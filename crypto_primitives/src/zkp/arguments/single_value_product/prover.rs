use super::proof::Proof;
use super::{Parameters, Statement, Witness};

use crate::error::CryptoError;
use crate::utils::rand::sample_vector;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::transcript::TranscriptProtocol;
use ark_std::rand::Rng;
use std::iter;

use ark_ff::Field;
use merlin::Transcript;

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
        statement: &'a Statement<Scalar, Comm>,
        witness: &'a Witness<'a, Scalar>,
    ) -> Self {
        Self {
            parameters,
            transcript: Transcript::new(b"single_value_product_argument"),
            statement,
            witness,
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) -> Result<Proof<Scalar, Comm>, CryptoError> {
        let mut transcript = self.transcript.clone();

        // generate vector b
        let b: Vec<Scalar> = iter::once(self.witness.a[0])
            .chain(
                self.witness
                    .a
                    .iter()
                    .skip(1)
                    .scan(self.witness.a[0], |st, elem| {
                        *st *= elem;
                        Some(*st)
                    }),
            )
            .collect();

        let d: Vec<Scalar> = sample_vector(rng, self.parameters.n);
        let mut deltas: Vec<Scalar> = sample_vector(rng, self.parameters.n - 2);
        deltas.insert(0, d[0]);
        deltas.push(Scalar::zero());

        // pick random r_d
        let r_d = Scalar::rand(rng);

        // pick random s_1, s_x
        let s_1 = Scalar::rand(rng);
        let s_x = Scalar::rand(rng);

        let d_commit = Comm::commit(&self.parameters.commit_key, &d, r_d)?;

        let minus_one = -Scalar::one();
        let delta_ds = deltas
            .iter()
            .take(deltas.len() - 1)
            .zip(d.iter().skip(1))
            .map(|(delta, d)| minus_one * delta * d)
            .collect::<Vec<_>>();

        let delta_commit = Comm::commit(&self.parameters.commit_key, &delta_ds, s_1)?;

        // skip frist a, skip first d, skip last b, and use all deltas
        let diffs = self
            .witness
            .a
            .iter()
            .skip(1)
            .zip(d.iter().skip(1))
            .zip(b.iter().take(b.len() - 1))
            .zip(deltas.iter().skip(1))
            .zip(deltas.iter().take(deltas.len() - 1))
            .map(
                |((((&a_i, &d_i), &b_i_minus_one), &delta_i), &delta_i_minus_1)| {
                    delta_i + minus_one * a_i * delta_i_minus_1 + minus_one * b_i_minus_one * d_i
                },
            )
            .collect::<Vec<_>>();

        let diff_commit = Comm::commit(&self.parameters.commit_key, &diffs, s_x)?;

        //public information
        transcript.append(b"commit_key", self.parameters.commit_key);
        transcript.append(b"a_commit", self.statement.a_commit);

        //commits
        transcript.append(b"d_commit", &d_commit);
        transcript.append(b"delta_commit", &delta_commit);
        transcript.append(b"diff_commit", &diff_commit);

        let x = transcript.challenge_scalar(b"x");

        let a_blinded = Self::blind(&self.witness.a, &d, x);
        let r_blinded = x * self.witness.random_for_a_commit + r_d;

        let b_blinded = Self::blind(&b, &deltas, x);
        let s_blinded = x * s_x + s_1;

        let proof = Proof {
            // round 1
            d_commit,
            delta_commit,
            diff_commit,

            // round 2
            a_blinded,
            b_blinded,
            r_blinded,
            s_blinded,
        };

        Ok(proof)
    }

    fn blind(x: &Vec<Scalar>, blinders: &Vec<Scalar>, challenge: Scalar) -> Vec<Scalar> {
        let blinded = x
            .iter()
            .zip(blinders.iter())
            .map(|(x, b)| challenge * x + b)
            .collect::<Vec<Scalar>>();

        blinded
    }
}
