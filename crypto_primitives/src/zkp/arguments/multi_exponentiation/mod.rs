pub mod proof;
pub mod prover;

use crate::homomorphic_encryption::HomomorphicEncryptionScheme;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::ArgumentOfKnowledge;
use ark_std::marker::PhantomData;
use ark_ff::Field;

pub struct MultiExponentiation<F : Field, Enc: HomomorphicEncryptionScheme<F>, Comm: HomomorphicCommitmentScheme<F>> {
    _encryption_scheme: PhantomData<Enc>,
    _commitment_scheme: PhantomData<Comm>
}

// impl ArgumentOfKnowledge for MultiExponentiation {
    
// }

/// Parameters for the multi-exponentiation argument. Contains the encryption public key, a commitment key
/// and a public group generator which will be used for masking.
pub struct Parameters<'a, F, Enc, Comm>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub public_key: &'a Enc::PublicKey,
    pub commit_key: &'a Comm::CommitKey,
    pub generator: Enc::Plaintext,
}

impl<'a, F, Enc, Comm> Parameters<'a, F, Enc, Comm>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub fn new(
        public_key: &'a Enc::PublicKey,
        commit_key: &'a Comm::CommitKey,
        generator: Enc::Plaintext,
    ) -> Self {
        Self {
            public_key,
            commit_key,
            generator,
        }
    }
}

/// Witness for the multi-exponentiation argument. Contains a hidden n-by-m matrix A, a vector of randoms r used to commit to
/// the columns of A and an aggregate re-encryption factor rho
pub struct Witness<'a, F, Enc, Comm>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub matrix_a: &'a Vec<Vec<Comm::Scalar>>,
    pub matrix_blinders: &'a Vec<Comm::Scalar>,
    pub rho: Enc::Randomness,
}

impl<'a, F, Enc, Comm> Witness<'a, F, Enc, Comm>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub fn new(
        matrix_a: &'a Vec<Vec<Comm::Scalar>>,
        matrix_blinders: &'a Vec<Comm::Scalar>,
        rho: Enc::Randomness,
    ) -> Self {
        Self {
            matrix_a,
            matrix_blinders,
            rho,
        }
    }
}

/// Statement for the multi-exponentiation argument. Contains an m-by-n matrix of ciphertexts matC, a ciphertext C
/// and a vector of commitments to the columns of a hidden n-by-m matrix A (see `Witness`) such that:
/// C is the aggregation of the re-encrypted ciphertexts using the blinding factors found in A.
pub struct Statement<'a, F, Enc, Comm>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub shuffled_ciphers: &'a Vec<Vec<Enc::Ciphertext>>,
    pub product: Enc::Ciphertext,
    pub commitments_to_exponents: &'a Vec<Comm::Commitment>,
}

impl<'a, F, Enc, Comm> Statement<'a, F, Enc, Comm>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub fn new(
        shuffled_ciphers: &'a Vec<Vec<Enc::Ciphertext>>,
        product: Enc::Ciphertext,
        commitments_to_exponents: &'a Vec<Comm::Commitment>,
    ) -> Self {
        Self {
            shuffled_ciphers,
            product,
            commitments_to_exponents,
        }
    }
}
