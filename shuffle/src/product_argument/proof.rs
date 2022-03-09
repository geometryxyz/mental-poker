use ark_ec::ProjectiveCurve;

use crate::error::Error;
use crate::product_argument::{hadamard_product_argument, single_value_product_argument};
use crate::product_argument::{Parameters, Statement};

pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub b_commit: C,
    pub hadamard_product_proof: hadamard_product_argument::proof::Proof<C>,
    pub single_value_proof: single_value_product_argument::proof::Proof<C>,
}

impl<C> Proof<C>
where
    C: ProjectiveCurve,
{
    pub fn verify(
        &self,
        proof_parameters: &Parameters<C>,
        statement: &Statement<C>,
    ) -> Result<(), Error> {
        statement.is_valid(proof_parameters)?;

        // Verifiy hadamrd product argument
        let hadamard_product_parameters = hadamard_product_argument::Parameters::<C>::new(
            proof_parameters.m,
            proof_parameters.n,
            proof_parameters.commit_key,
        );

        let hadamard_product_statement =
            hadamard_product_argument::Statement::new(statement.commitments_to_a, self.b_commit);

        self.hadamard_product_proof
            .verify(&hadamard_product_parameters, &hadamard_product_statement)?;
        // verify single value product argument
        let single_value_product_parameters = single_value_product_argument::Parameters::<C>::new(
            proof_parameters.n,
            proof_parameters.commit_key,
        );

        let single_value_product_statement =
            single_value_product_argument::Statement::<C>::new(self.b_commit, statement.b);

        self.single_value_proof.verify(
            &single_value_product_parameters,
            &single_value_product_statement,
        )?;

        Ok(())
    }
}
