pub mod proof;
pub mod prover;
pub mod tests;

use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::ArgumentOfKnowledge;
use ark_ff::Field;
use ark_std::{marker::PhantomData, rand::Rng};

pub struct HadamardProductArgument<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    _field: PhantomData<&'a F>,
    _commitment_scheme: PhantomData<&'a Comm>,
}

impl<'a, Scalar, Comm> ArgumentOfKnowledge for HadamardProductArgument<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    type CommonReferenceString = Parameters<'a, Scalar, Comm>;
    type Statement = Statement<'a, Scalar, Comm>;
    type Witness = Witness<'a, Scalar>;
    type Proof = proof::Proof<Scalar, Comm>;

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

/// Parameters for the Hadamard product argument. Contains a commitment key and the matrix dimensions.
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

/// Witness for the Hadamard product argument. Contains a matrix A of size, vector r, vector b and scalar s such that:
/// b is the Hadamard product of the columns of A, `commitment_to_a` (see `Statement`) is a vector of commitments to the
/// columns of A using the randoms r and `commitment_to_b` (see `Statement`) is a commitment to the vector b using random s.
pub struct Witness<'a, Scalar>
where
    Scalar: Field,
{
    pub matrix_a: &'a Vec<Vec<Scalar>>,
    pub randoms_for_a_commit: &'a Vec<Scalar>,
    pub vector_b: &'a Vec<Scalar>,
    pub random_for_b_commit: Scalar,
}

impl<'a, Scalar> Witness<'a, Scalar>
where
    Scalar: Field,
{
    pub fn new(
        matrix_a: &'a Vec<Vec<Scalar>>,
        randoms_for_a_commit: &'a Vec<Scalar>,
        vector_b: &'a Vec<Scalar>,
        random_for_b_commit: Scalar,
    ) -> Self {
        Self {
            matrix_a,
            randoms_for_a_commit,
            vector_b,
            random_for_b_commit,
        }
    }
}

/// Statement for the Hadamard product argument. Contains a vector `commitment_to_a` of commitments to the columns
/// of matrix `A` using the randoms `r` (see `Witness`) and a point `commitment_to_b`, which is a commitment to the
/// vector b using the random `s` (see `Witness`).
pub struct Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub commitment_to_a: &'a Vec<Comm::Commitment>,
    pub commitment_to_b: Comm::Commitment,
}

impl<'a, Scalar, Comm> Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(
        commitment_to_a: &'a Vec<Comm::Commitment>,
        commitment_to_b: Comm::Commitment,
    ) -> Self {
        Self {
            commitment_to_a,
            commitment_to_b,
        }
    }
}
