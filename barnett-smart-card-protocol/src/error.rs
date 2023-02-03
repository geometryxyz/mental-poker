use proof_essentials::error::CryptoError;
use thiserror::Error;

/// This is an error that could occur when running a cryptographic primitive
#[derive(Error, Debug, PartialEq)]
pub enum CardProtocolError {
    #[error("Failed to verify proof")]
    ProofVerificationError(#[from] CryptoError),

    #[error("IoError: {0}")]
    IoError(String),
}

impl From<std::io::Error> for CardProtocolError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}
