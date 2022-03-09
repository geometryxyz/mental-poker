use super::{proof::Proof, Parameters, Statement, Witness};

use crate::{
    product_argument::*,
    utils::{
        HadamardProduct, HadamardProductCalculator, HomomorphicCommitment, PedersenCommitment,
        RandomSampler, ScalarSampler,
    },
};

use ark_ec::ProjectiveCurve;
use ark_ff::One;
use rand::Rng;

pub struct Prover<'a, C>
where
    C: ProjectiveCurve,
{
    parameters: &'a Parameters<'a, C>,
    statement: &'a Statement<'a, C>,
    witness: &'a Witness<'a, C>,
}

impl<'a, C: ProjectiveCurve> Prover<'a, C> {
    pub fn new(
        parameters: &'a Parameters<'a, C>,
        statement: &'a Statement<'a, C>,
        witness: &'a Witness<'a, C>,
    ) -> Self {
        Self {
            parameters,
            statement,
            witness,
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) -> Proof<C> {
        let s = ScalarSampler::<C>::sample_element(rng);
        let product_along_rows = self
            .witness
            .matrix_a
            .iter()
            .fold(vec![C::ScalarField::one(); self.parameters.n], |x, y| {
                HadamardProductCalculator::<C>::scalars_by_scalars(&x, &y).unwrap()
            });

        let b_commit = PedersenCommitment::<C>::commit_vector(
            self.parameters.commit_key,
            &product_along_rows,
            s,
        );

        // Engage in Hadamard Product Argument for b_commit and the `product_along_rows` as its witness:
        // This will show that each entry in `product_along_rows` is computed correctly
        let hadamard_product_parameters = hadamard_product_argument::Parameters::<C>::new(
            self.parameters.m,
            self.parameters.n,
            &self.parameters.commit_key,
        );

        let hadamard_product_statement =
            hadamard_product_argument::Statement::new(&self.statement.commitments_to_a, b_commit);

        let hadamard_product_witness = hadamard_product_argument::Witness::<C>::new(
            self.witness.matrix_a,
            self.witness.randoms_for_a_commit,
            &product_along_rows,
            s,
        );

        let hadamard_product_prover = hadamard_product_argument::prover::Prover::new(
            &hadamard_product_parameters,
            &hadamard_product_statement,
            &hadamard_product_witness,
        );

        let hadamard_product_proof = hadamard_product_prover.prove(rng);

        // Engage in single value product argument for b_commit and b as a statement:
        // This will show that our claimed product b is indeed the product of the values in
        // `product_along_rows`
        let single_value_product_parameters = single_value_product_argument::Parameters::<C>::new(
            self.parameters.n,
            &self.parameters.commit_key,
        );
        let single_value_product_witness =
            single_value_product_argument::Witness::<C>::new(&product_along_rows, &s);

        let single_value_product_statement =
            single_value_product_argument::Statement::<C>::new(b_commit, self.statement.b);

        let single_value_prover = single_value_product_argument::prover::Prover::new(
            &single_value_product_parameters,
            &single_value_product_statement,
            &single_value_product_witness,
        );

        let single_value_proof = single_value_prover.prove(rng);

        Proof {
            b_commit,
            hadamard_product_proof,
            single_value_proof,
        }
    }
}
