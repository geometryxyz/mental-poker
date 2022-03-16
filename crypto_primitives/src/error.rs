use thiserror::Error;

/// This is an error that could occur when running a cryptograhic primitive
#[derive(Error, Debug, PartialEq)]
pub enum CryptoError {
    #[error("Failed to verify {0} proof")]
    ProofVerificationError(String),

    #[error("Failed to output a {0} commitment: values {1} > bases {2}")]
    CommitmentLengthError(String, usize, usize),

    #[error("Dot Product error: left = {0} - right = {1}")]
    DotProductLengthError(usize, usize),

    #[error("Bilinear Map error: left = {0} - right = {1}")]
    BilinearMapLengthError(usize, usize),

    #[error("Hadamard Product error: left = {0} - right = {1}")]
    HadamardProductLengthError(usize, usize),

    #[error("Cannot cast vector of size {0} to matrix of {1} by {2}")]
    VectorCastingError(usize, usize, usize),

    #[error("Diagonals Error: left = {0} - right = {1}")]
    DiagonalLengthError(usize, usize),

    #[error("InvalidProductArgumentStatement")]
    InvalidProductArgumentStatement,

    #[error("InvalidShuffleStatement")]
    InvalidShuffleStatement,
}
