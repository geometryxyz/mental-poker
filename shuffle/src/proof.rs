use ark_ec::ProjectiveCurve;
use ark_ff::{Zero, PrimeField};

use crate::error::Error;
use crate::{product_argument, multi_exponent_argument};
use super::{Parameters, Statement};
use ark_crypto_primitives::{encryption::{elgamal::{Parameters as ElGamalParameters}}};
use merlin::Transcript;
use crate::{
    transcript::TranscriptProtocol,
    utils::{HomomorphicCommitment, PedersenCommitment, DotProduct, DotProductCalculator}
};
use std::iter;

pub struct Proof<C> 
where 
    C: ProjectiveCurve
{
    pub a_commits: Vec<C>,
    pub b_commits: Vec<C>,
    pub product_argument_proof: product_argument::proof::Proof<C>,
    pub multi_exp_proof: multi_exponent_argument::proof::Proof<C>
}

impl<C> Proof<C> 
    where
        C: ProjectiveCurve
{
    pub fn verify(&self, proof_parameters: &Parameters<C>, statement: &Statement<C>, encryption_parameters: &ElGamalParameters<C>) -> Result<(), Error> {
        let mut transcript = Transcript::new(b"shuffle_argument");
        // Public data
        transcript.append(b"public_key", proof_parameters.public_key);
        transcript.append(b"commit_key", proof_parameters.commit_key);

        // statement
        transcript.append(b"ciphers", statement.input_ciphers);
        transcript.append(b"shuffled", statement.shuffled_ciphers);
        transcript.append(b"m", &statement.m);
        transcript.append(b"n", &statement.n);

        // round 1
        transcript.append(b"a_commits", &self.a_commits);
        let x: C::ScalarField = transcript.challenge_scalar(b"x");

        let challenge_powers =
            iter::once(x)
            .chain(
                (1..statement.m * statement.n).scan(x, |current_power, _exp| {
                    *current_power *= x;
                    Some(*current_power)
                })
            )
        .collect::<Vec<_>>();

        // round 2
        transcript.append(b"b_commits", &self.b_commits);

        let y: C::ScalarField = transcript.challenge_scalar(b"y");
        let z: C::ScalarField = transcript.challenge_scalar(b"z");
        
        // PRODUCT ARGUMENT -------------------------------------------------------------
        let z_vec = vec![-z; statement.n];
        let zero = C::ScalarField::zero();
        let single_neg_z_commit = PedersenCommitment::<C>::commit_vector(
            proof_parameters.commit_key,
            &z_vec,
            zero
        );
        let neg_z_commit = vec![single_neg_z_commit; statement.m];

        let c_d = self.a_commits.iter()
            .zip(self.b_commits.iter())
            .map(|(&a, &b)| a.mul(y.into_repr()) + b)
            .collect::<Vec<C>>();

                
        let verifier_side_expected_product = (1..=statement.n * statement.m)
            .zip(challenge_powers.iter())
            .map(|(i, x_pow_i)| y*C::ScalarField::from(i as u64) + x_pow_i - z)
            .product();

        let product_argument_parameters = product_argument::Parameters::<C>::new(
            statement.m,
            statement.n,
            proof_parameters.commit_key
        );

        let commitments_to_a = c_d.iter().zip(neg_z_commit.iter()).map(|(&d_commit, &z_commit)| d_commit + z_commit).collect::<Vec<_>>();
        let product_argument_statement = product_argument::Statement::new(
            &commitments_to_a,
            verifier_side_expected_product
        );

        self.product_argument_proof.verify(&product_argument_parameters, &product_argument_statement)?;


        // MULTI-EXPONENTIATION ARGUMENT -------------------------------------------------------
        let multi_exp_parameters = multi_exponent_argument::Parameters::<C>::new(
            &proof_parameters.public_key,
            &proof_parameters.commit_key,
            encryption_parameters.generator
        );

        let shuffled_chunks = statement.shuffled_ciphers.chunks(statement.n).map(|c| c.to_vec()).collect::<Vec<_>>();

        let product = DotProductCalculator::<C>::scalars_by_ciphers(
            &challenge_powers,
            statement.input_ciphers
        ).unwrap();

        let multi_exp_statement = multi_exponent_argument::Statement::<C>::new(
            &shuffled_chunks,
            product,
            &self.b_commits
         );

        self.multi_exp_proof.verify(&multi_exp_parameters, encryption_parameters, &multi_exp_statement)?;

        Ok(())
    }
}