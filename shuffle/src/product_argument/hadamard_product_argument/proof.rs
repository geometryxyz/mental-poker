use crate::{
    error::Error,
    product_argument::{
        hadamard_product_argument::{Parameters, Statement},
        zero_argument::{self, YMapping},
    },
    transcript::TranscriptProtocol,
    utils::{HomomorphicCommitment, PedersenCommitment},
};
use ark_ec::ProjectiveCurve;
use ark_ff::{One, PrimeField, Zero};
use merlin::Transcript;
use std::iter;

pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    // Round 1
    pub b_commits: Vec<C>,

    // Round 2
    pub zero_arg_proof: zero_argument::proof::Proof<C>,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify(
        &self,
        proof_parameters: &Parameters<C>,
        statement: &Statement<C>,
    ) -> Result<(), Error> {
        let mut transcript = Transcript::new(b"hadamard_product_argument");

        // check c_b_1 = c_a_1
        if statement.commitment_to_a[0] != self.b_commits[0] {
            return Err(Error::HadamardProductVerificationError);
        }

        // check c_b_m = c_b
        if statement.commitment_to_b != self.b_commits[proof_parameters.m - 1] {
            return Err(Error::HadamardProductVerificationError);
        }

        // Public parameters
        transcript.append(b"commit_key", proof_parameters.commit_key);
        transcript.append(b"m", &proof_parameters.m);
        transcript.append(b"n", &proof_parameters.n);

        // Commited values
        transcript.append(b"b_commit", &self.b_commits);

        // Extract challenges
        let x: C::ScalarField = transcript.challenge_scalar(b"x");
        let y: C::ScalarField = transcript.challenge_scalar(b"y");

        // Precompute all powers of the x challenge from 0 to number_of_diagonals
        let x_challenge_powers = iter::once(C::ScalarField::one())
            .chain(iter::once(x))
            .chain((1..proof_parameters.m - 1).scan(x, |current_power, _exp| {
                *current_power *= x;
                Some(*current_power)
            }))
            .collect::<Vec<_>>();

        // Use the second challenge to define our bilinear mapping
        let prover_mapping = YMapping::<C>::new(y, proof_parameters.n);

        // Use challenge x and the b commits to compute the d commits
        let mut c_d_i = self
            .b_commits
            .iter()
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(&b_i_commit, &x_power_i)| b_i_commit.mul(x_power_i.into_repr()))
            .collect::<Vec<C>>();

        let temp_x_c_d_shifted = self
            .b_commits
            .iter()
            .skip(1)
            .zip(x_challenge_powers.iter().skip(1))
            .map(|(&b_i_commit, &x_power_i)| b_i_commit.mul(x_power_i.into_repr()))
            .collect::<Vec<C>>();

        let final_cd: C = temp_x_c_d_shifted.iter().fold(C::zero(), |acc, x| acc + x);
        c_d_i.push(final_cd);

        // Engage in zero argument
        let zero_arg_params = zero_argument::Parameters::<C>::new(
            proof_parameters.m,
            proof_parameters.n,
            &proof_parameters.commit_key,
        );

        let minus_one = -C::ScalarField::one();
        let vec_minus_ones = vec![minus_one; proof_parameters.n];
        let minus_ones_commit = PedersenCommitment::<C>::commit_vector(
            proof_parameters.commit_key,
            &vec_minus_ones,
            C::ScalarField::zero(),
        );
        let vec_commits_to_a: Vec<C> = [&statement.commitment_to_a[1..], &[minus_ones_commit]]
            .concat()
            .to_vec();

        let zero_arg_statement =
            zero_argument::Statement::<C>::new(&vec_commits_to_a, &c_d_i, &prover_mapping);

        match self
            .zero_arg_proof
            .verify(&zero_arg_params, &zero_arg_statement)
        {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::HadamardProductVerificationError),
        }
    }
}
