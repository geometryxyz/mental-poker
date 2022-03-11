use thiserror::Error;

/// This is an error that could occur when running a cryptograhic primitive
#[derive(Error, Debug, PartialEq)]
pub enum CryptoError {
    #[error("Failed to verify {0} proof")]
    ProofVerificationError(String),

    #[error("Failed to output a {0} commitment: values {1} > bases {2}")]
    CommitmentLengthError(String, usize, usize),
}
