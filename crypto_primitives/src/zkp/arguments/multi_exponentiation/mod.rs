pub mod proof;
pub mod prover;
mod tests;

use crate::homomorphic_encryption::HomomorphicEncryptionScheme;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use ark_ff::Field;
use ark_std::marker::PhantomData;
// use crate::error::CryptoError;
// use crate::zkp::ArgumentOfKnowledge;

pub struct MultiExponentiation<
    'a,
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
> {
    _field: PhantomData<&'a F>,
    _encryption_scheme: PhantomData<&'a Enc>,
    _commitment_scheme: PhantomData<&'a Comm>,
}

// impl<'a, F, Enc, Comm> ArgumentOfKnowledge for MultiExponentiation<'a, F, Enc, Comm>
// where
//     F: Field,
//     Enc: HomomorphicEncryptionScheme<F>,
//     Comm: HomomorphicCommitmentScheme<F>,
// {
//     type CommonReferenceString = Parameters<'a, F, Enc, Comm>;
//     type Statement = Statement<'a, F, Enc, Comm>;
//     type Witness = Witness<'a, F>;
//     type Proof = proof::Proof<F, Enc, Comm>;

//     // fn setup<R: Rng>(rng: &mut R) -> Result<Self::CommonReferenceString, CryptoError> {
//     //     let encrypt_parameters = Enc::setup(rng);
//     //     let (pk, _) =
//     // }

//     fn prove(
//         common_reference_string: &Self::CommonReferenceString,
//         statement: &Self::Statement,
//         witness: &Self::Witness,
//     ) -> Result<Self::Proof, CryptoError> {
//         let prover = prover::Prover::new(&common_reference_string, &statement, &witness);
//         let proof = prover.prove()?;

//         Ok(proof)
//     }

//     fn verify(
//         common_reference_string: &Self::CommonReferenceString,
//         statement: &Self::Statement,
//         proof: &Self::Proof,
//     ) -> Result<(), CryptoError> {
//         proof.verify(&common_reference_string, &statement)
//     }
// }

/// Parameters for the multi-exponentiation argument. Contains the encryption public key, a commitment key
/// and a public group generator which will be used for masking.
pub struct Parameters<'a, F, Enc, Comm>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub encrypt_parameters: &'a Enc::Parameters,
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
        encrypt_parameters: &'a Enc::Parameters,
        public_key: &'a Enc::PublicKey,
        commit_key: &'a Comm::CommitKey,
        generator: Enc::Plaintext,
    ) -> Self {
        Self {
            encrypt_parameters,
            public_key,
            commit_key,
            generator,
        }
    }
}

/// Witness for the multi-exponentiation argument. Contains a hidden n-by-m matrix A, a vector of randoms r used to commit to
/// the columns of A and an aggregate re-encryption factor rho
pub struct Witness<'a, Scalar>
where
    Scalar: Field,
{
    pub matrix_a: &'a Vec<Vec<Scalar>>,
    pub matrix_blinders: &'a Vec<Scalar>,
    pub rho: Scalar,
}

impl<'a, Scalar> Witness<'a, Scalar>
where
    Scalar: Field,
{
    pub fn new(
        matrix_a: &'a Vec<Vec<Scalar>>,
        matrix_blinders: &'a Vec<Scalar>,
        rho: Scalar,
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
pub struct Statement<'a, Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub shuffled_ciphers: &'a Vec<Vec<Enc::Ciphertext>>,
    pub product: Enc::Ciphertext,
    pub commitments_to_exponents: &'a Vec<Comm::Commitment>,
}

impl<'a, Scalar, Enc, Comm> Statement<'a, Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
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
