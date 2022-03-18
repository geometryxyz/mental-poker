use super::{proof::Proof, Parameters, Statement, Witness};

use crate::error::CryptoError;
use crate::utils::vector_arithmetic::hadamard_product as compute_hadamard_product;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::{
    arguments::{hadamard_product, single_value_product},
    ArgumentOfKnowledge,
};
use ark_std::rand::Rng;

use ark_ff::Field;

pub struct Prover<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    parameters: &'a Parameters<'a, Scalar, Comm>,
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
            statement,
            witness,
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) -> Result<Proof<Scalar, Comm>, CryptoError> {
        let s = Scalar::rand(rng);

        let mut product_along_rows = vec![Scalar::one(); self.parameters.n];
        for x in self.witness.matrix_a {
            product_along_rows = compute_hadamard_product(&x, &product_along_rows)?;
        }

        let b_commit = Comm::commit(self.parameters.commit_key, &product_along_rows, s)?;

        // Engage in Hadamard Product Argument for b_commit and the `product_along_rows` as its witness:
        // This will show that each entry in `product_along_rows` is computed correctly
        let hadamard_product_parameters = hadamard_product::Parameters::new(
            self.parameters.m,
            self.parameters.n,
            self.parameters.commit_key,
        );

        let hadamard_product_statement =
            hadamard_product::Statement::new(&self.statement.commitments_to_a, b_commit);

        let hadamard_product_witness = hadamard_product::Witness::new(
            self.witness.matrix_a,
            self.witness.randoms_for_a_commit,
            &product_along_rows,
            s,
        );

        let hadamard_product_proof = hadamard_product::HadamardProductArgument::prove(
            rng,
            &hadamard_product_parameters,
            &hadamard_product_statement,
            &hadamard_product_witness,
        )?;

        // Engage in single value product argument for b_commit and b as a statement:
        // This will show that our claimed product b is indeed the product of the values in
        // `product_along_rows`
        let single_value_product_parameters =
            single_value_product::Parameters::new(self.parameters.n, self.parameters.commit_key);

        let single_value_product_witness =
            single_value_product::Witness::new(&product_along_rows, &s);

        let single_value_product_statement =
            single_value_product::Statement::new(&b_commit, self.statement.b);

        let single_value_proof = single_value_product::SingleValueProductArgument::prove(
            rng,
            &single_value_product_parameters,
            &single_value_product_statement,
            &single_value_product_witness,
        )?;

        let proof = Proof {
            b_commit,
            hadamard_product_proof,
            single_value_proof,
        };

        Ok(proof)
    }
}
