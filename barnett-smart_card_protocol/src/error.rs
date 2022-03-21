use crypto_primitives::error::CryptoError;
use thiserror::Error;

/// This is an error that could occur when running a cryptograhic primitive
#[derive(Error, Debug, PartialEq)]
pub enum CardProtocolError {
    #[error("Failed to verify proof")]
    ProofVerificationError(#[from] CryptoError),
}
