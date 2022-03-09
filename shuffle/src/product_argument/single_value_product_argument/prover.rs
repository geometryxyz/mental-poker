use ark_ec::ProjectiveCurve;
use ark_ff::{One, Zero};

use merlin::Transcript;
use rand::Rng;
use std::iter;

use crate::{
    product_argument::single_value_product_argument::{
        proof::Proof, Parameters, Statement, Witness,
    },
    transcript::TranscriptProtocol,
    utils::{HomomorphicCommitment, PedersenCommitment, RandomSampler, ScalarSampler},
};

pub struct Prover<'a, C>
where
    C: ProjectiveCurve,
{
    parameters: &'a Parameters<'a, C>,
    transcript: Transcript,
    statement: &'a Statement<C>,
    witness: &'a Witness<'a, C>,
}

impl<'a, C> Prover<'a, C>
where
    C: ProjectiveCurve,
{
    pub fn new(
        parameters: &'a Parameters<'a, C>,
        statement: &'a Statement<C>,
        witness: &'a Witness<'a, C>,
    ) -> Self {
        Self {
            parameters,
            transcript: Transcript::new(b"single_value_product_argument"),
            statement,
            witness,
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) -> Proof<C> {
        let mut transcript = self.transcript.clone();

        // generate vector b
        let b: Vec<C::ScalarField> = iter::once(self.witness.a[0])
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

        let d = ScalarSampler::<C>::sample_vector(rng, self.parameters.n);
        let mut deltas = ScalarSampler::<C>::sample_vector(rng, self.parameters.n - 2);
        deltas.insert(0, d[0]);
        deltas.push(C::ScalarField::zero());

        // // sample rd
        let r_d = ScalarSampler::<C>::sample_element(rng);

        // sample s1, sx
        let s_1 = ScalarSampler::<C>::sample_element(rng);
        let s_x = ScalarSampler::<C>::sample_element(rng);

        let d_commit = PedersenCommitment::<C>::commit_vector(&self.parameters.commit_key, &d, r_d);

        let minus_one = -C::ScalarField::one();
        let delta_ds = deltas
            .iter()
            .take(deltas.len() - 1)
            .zip(d.iter().skip(1))
            .map(|(delta, d)| minus_one * delta * d)
            .collect::<Vec<_>>();

        let delta_commit =
            PedersenCommitment::<C>::commit_vector(&self.parameters.commit_key, &delta_ds, s_1);

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

        let diff_commit =
            PedersenCommitment::<C>::commit_vector(&self.parameters.commit_key, &diffs, s_x);

        //public information
        transcript.append(b"commit_key", self.parameters.commit_key);
        transcript.append(b"a_commit", &self.statement.a_commit);

        //commits
        transcript.append(b"d_commit", &d_commit);
        transcript.append(b"delta_commit", &delta_commit);
        transcript.append(b"diff_commit", &diff_commit);

        let x = transcript.challenge_scalar(b"x");

        let a_blinded = Self::blind(&self.witness.a, &d, x);
        let r_blinded = x * self.witness.random_for_a_commit + r_d;

        let b_blinded = Self::blind(&b, &deltas, x);
        let s_blinded = x * s_x + s_1;

        Proof {
            // round 1
            d_commit,
            delta_commit,
            diff_commit,

            // round 2
            a_blinded,
            b_blinded,
            r_blinded,
            s_blinded,
        }
    }

    fn blind(
        x: &Vec<C::ScalarField>,
        blinders: &Vec<C::ScalarField>,
        challenge: C::ScalarField,
    ) -> Vec<C::ScalarField> {
        let blinded = x
            .iter()
            .zip(blinders.iter())
            .map(|(x, b)| challenge * x + b)
            .collect::<Vec<C::ScalarField>>();

        blinded
    }
}
