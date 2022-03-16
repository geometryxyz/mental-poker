pub mod proof;
pub mod prover;
pub mod tests;

use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::ArgumentOfKnowledge;
use ark_ff::Field;
use ark_std::{marker::PhantomData, rand::Rng};

pub struct ProductArgument<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    _field: PhantomData<&'a F>,
    _commitment_scheme: PhantomData<&'a Comm>,
}

impl<'a, Scalar, Comm> ArgumentOfKnowledge for ProductArgument<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    type CommonReferenceString = Parameters<'a, Scalar, Comm>;
    type Statement = Statement<'a, Scalar, Comm>;
    type Witness = Witness<'a, Scalar>;
    type Proof = proof::Proof<Scalar, Comm>;

    // // fn setup<R: Rng>(rng: &mut R) -> Result<Self::CommonReferenceString, CryptoError>;

    fn prove<R: Rng>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, CryptoError> {
        let prover = prover::Prover::new(common_reference_string, statement, witness);
        let proof = prover.prove(rng)?;

        Ok(proof)
    }

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
    ) -> Result<(), CryptoError> {
        proof.verify(&common_reference_string, &statement)
    }
}

/// Parameters for the product argument
pub struct Parameters<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub commit_key: &'a Comm::CommitKey,
    pub m: usize,
    pub n: usize,
}

impl<'a, Scalar, Comm> Parameters<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(m: usize, n: usize, commit_key: &'a Comm::CommitKey) -> Self {
        Self { commit_key, m, n }
    }
}

/// Witness for the product argument. Contains a matrix A for which we want to claim the product b (see [Statement])
/// and randoms which will have been used to commit to each column of A.
pub struct Witness<'a, Scalar: Field> {
    pub matrix_a: &'a Vec<Vec<Scalar>>,
    pub randoms_for_a_commit: &'a Vec<Scalar>,
}

impl<'a, Scalar> Witness<'a, Scalar>
where
    Scalar: Field,
{
    pub fn new(matrix_a: &'a Vec<Vec<Scalar>>, randoms_for_a_commit: &'a Vec<Scalar>) -> Self {
        Self {
            matrix_a,
            randoms_for_a_commit,
        }
    }
}

/// Statement for the product argument. Contains a vector of commitments to the columns of matrix A (see [Witness])
/// and a scalar b which is claimed to be the product of all the cells in A.
pub struct Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub commitments_to_a: &'a Vec<Comm::Commitment>,
    pub b: Scalar,
}

impl<'a, Scalar, Comm> Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(commitments_to_a: &'a Vec<Comm::Commitment>, b: Scalar) -> Self {
        Self {
            commitments_to_a,
            b,
        }
    }

    pub fn is_valid(&self, parameters: &Parameters<Scalar, Comm>) -> Result<(), CryptoError> {
        if self.commitments_to_a.len() != parameters.m {
            return Err(CryptoError::InvalidProductArgumentStatement);
        }
        Ok(())
    }
}
