use thiserror::Error;

/// This is an error that could occur during the hash to curve process
#[derive(Error, Debug, PartialEq)]
pub enum CryptoError {
    #[error("Failed to verify {0} proof")]
    ProofVerificationError(String),
}
