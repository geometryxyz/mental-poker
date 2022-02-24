use super::{Statement, Parameters, Witness};

use crate::{
    error::Error,
    utils::{
        ScalarSampler, RandomSampler, PedersenCommitment, HomomorphicCommitment, DotProduct, DotProductCalculator, HadamardProduct, HadamardProductCalculator}, 
    transcript::TranscriptProtocol,
    product_argument::{zero_argument::{YMapping, BilinearMap}, zero_argument}
};

use ark_ec::{ProjectiveCurve};
use ark_ff::{Zero, One, PrimeField};
use merlin::Transcript;
use rand::Rng;
use std::iter;

pub struct Prover<'a, C>
where 
    C: ProjectiveCurve,
{
    parameters: &'a Parameters<'a, C>,
    transcript: Transcript,
    statement: &'a Statement<'a, C>,
    witness: &'a Witness<'a, C>, 
}

impl<'a, C: ProjectiveCurve> Prover<'a, C> {
    pub fn new(
        parameters: &'a Parameters<'a, C>,
        statement: &'a Statement<'a, C>,
        witness: &'a Witness<'a, C>
    ) -> Self {

        Self {
            parameters, 
            transcript: Transcript::new(b"hadamard_product_argument"),
            statement, 
            witness
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) {
        let mut transcript = self.transcript.clone();

        let mut acc = vec![C::ScalarField::one(); self.parameters.n];

        let b = self.witness.matrix_a.iter().map(|x| {
            acc = acc.iter().zip(x.iter()).map(|(&s_a, &s_b)| s_a * s_b).collect();
            acc.clone()
        }).collect::<Vec<_>>();

        let mut s = ScalarSampler::<C>::sample_vector(rng, self.parameters.m - 2);

        let b_commit = 
        iter::once(self.statement.commitment_to_a[0])
        .chain(
            b.iter().take(b.len() - 1).skip(1).zip(s.iter()).map(|(b_i, &s_i)| {
                PedersenCommitment::<C>::commit_vector(self.parameters.commit_key, b_i, s_i)
            })
        )
        .chain(iter::once(self.statement.commitment_to_b))
        .collect::<Vec<C>>();

        s.insert(0, self.witness.randoms_for_a_commit[0]);
        s.push(self.witness.random_for_b_commit);

        // Public parameters
        transcript.append(b"commit_key", self.parameters.commit_key);
        transcript.append(b"m", &self.parameters.m);
        transcript.append(b"n", &self.parameters.n);

        // Random values
        transcript.append(b"s", &s);

        // Commited values
        transcript.append(b"b_commit", &b_commit);

        // Challenges
        let x: C::ScalarField = transcript.challenge_scalar(b"x");
        let y: C::ScalarField = transcript.challenge_scalar(b"y");

        // Precompute all powers of the challenge from 0 to number_of_diagonals
        let x_challenge_powers =
        iter::once(C::ScalarField::one())
        .chain(iter::once(x))
        .chain(
            (1..self.parameters.m-1).scan(x, |current_power, _exp| {
                *current_power *= x;
                Some(*current_power)
            })
        )
        .collect::<Vec<_>>();

        // Prepare statement
        let prover_mapping = YMapping::<C>::new(y, self.parameters.n);

        let minus_one = -C::ScalarField::one();
        let vec_minus_ones = vec![minus_one; self.parameters.n];
        let minus_ones_commit = PedersenCommitment::<C>::commit_vector(self.parameters.commit_key, &vec_minus_ones, C::ScalarField::zero());

        let vec_commits_to_a: Vec<C> = [&self.statement.commitment_to_a[..], &[minus_ones_commit]].concat().to_vec();

        let mut c_d_i = b_commit.iter().zip(x_challenge_powers.iter().skip(1)).map(|(&b_i_commit, &x_power_i)| {
            b_i_commit.mul(x_power_i.into_repr())
        }).collect::<Vec<C>>();

        let c_d: C = c_d_i.iter().sum();
        c_d_i.push(c_d);

        // prepare witness
        let vec_openings_to_a = [&self.witness.matrix_a[1..], &[vec_minus_ones]].concat().to_vec();
        let vec_randoms_for_a = [&self.witness.randoms_for_a_commit[1..], &[C::ScalarField::zero()]].concat().to_vec();

        let final_t = DotProductCalculator::<C>::scalars_by_scalars(&x_challenge_powers[1..=self.parameters.m-1].to_vec(), &s[2..=self.parameters.m].to_vec()).unwrap();
        let vec_randoms_for_d = 
        x_challenge_powers.iter().skip(1).zip(s.iter()).map(|(&x_power_i, &s_i)| {
            x_power_i * s_i
        })
        .chain(iter::once(final_t))
        .collect::<Vec<C::ScalarField>>();

        let temp_x_b = b[2..=self.parameters.m].to_vec().iter().zip(x_challenge_powers.iter().skip(1)).map(|(b_chunk, &x_power_i)| {
            let x_power_i_vector = vec![x_power_i; self.parameters.n];
            HadamardProductCalculator::<C>::scalars_by_scalars(b_chunk, &x_power_i_vector).unwrap()
        }).collect::<Vec<Vec<C::ScalarField>>>();

        let final_d = temp_x_b.into_iter().reduce(|x, y| {
            x.iter().zip(y.iter()).map(|(&s_a, &s_b)| s_a + s_b).collect()
        }).unwrap();

        let vec_openings_to_d = 
        b.iter().zip(x_challenge_powers.iter().skip(1)).map(|(b_chunk, &x_power_i)| {
            let x_power_i_vector = vec![x_power_i; self.parameters.n];
            HadamardProductCalculator::<C>::scalars_by_scalars(b_chunk, &x_power_i_vector).unwrap()
        })
        .chain(iter::once(final_d))
        .collect::<Vec<_>>();

        let zero_arg_statement = zero_argument::Statement::<C>::new(&vec_commits_to_a, &c_d_i, &prover_mapping);
        let zero_arg_params = zero_argument::Parameters::<C>::new(self.parameters.m, self.parameters.n, &self.parameters.commit_key);
        let zero_arg_witness = zero_argument::Witness::<C>::new(&vec_openings_to_a, &vec_randoms_for_a, &vec_openings_to_d, &vec_randoms_for_d);

        let zero_arg_prover = crate::product_argument::zero_argument::prover::Prover::<C>::new(&zero_arg_params, &zero_arg_statement, &zero_arg_witness);

        let zero_arg_proof = zero_arg_prover.prove(rng);
    }
}