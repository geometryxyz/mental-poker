use thiserror::Error;

/// This is an error that could occur during the hash to curve process
#[derive(Error, Debug, PartialEq)]
pub enum UtilError {
    #[error("Input lenghts mismatch when computing {}: left = {0} // right = {1}")]
    LengthError (String, usize, usize),
}

