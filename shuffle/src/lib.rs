#![crate_name = "shuffle"]

pub mod config;
pub mod error;
pub mod permutation;
pub mod tests;
pub mod transcript;
pub mod utils;

pub mod proof;
pub mod prover;

pub mod multi_exponent_argument;
pub mod product_argument;

use crate::error::Error;
use crate::permutation::Permutation;
use ark_ec::ProjectiveCurve;
use verifiable_threshold_masking_protocol::discrete_log_vtmp::ElgamalCipher;

/// Parameters for the product argument
pub struct Parameters<'a, C: ProjectiveCurve> {
    pub public_key: &'a C::Affine,
    pub commit_key: &'a Vec<C::Affine>,
}

impl<'a, C: ProjectiveCurve> Parameters<'a, C> {
    pub fn new(public_key: &'a C::Affine, commit_key: &'a Vec<C::Affine>) -> Self {
        Self {
            public_key,
            commit_key,
        }
    }
}

/// Statement of a shuffle. Contains the input ciphertexts, the output ciphertexts and the matrix dimensions
pub struct Statement<'a, C: ProjectiveCurve> {
    pub input_ciphers: &'a Vec<ElgamalCipher<C>>,
    pub shuffled_ciphers: &'a Vec<ElgamalCipher<C>>,
    pub m: usize,
    pub n: usize,
}

impl<'a, C: ProjectiveCurve> Statement<'a, C> {
    pub fn new(
        input_ciphers: &'a Vec<ElgamalCipher<C>>,
        shuffled_ciphers: &'a Vec<ElgamalCipher<C>>,
        m: usize,
        n: usize,
    ) -> Self {
        Self {
            input_ciphers,
            shuffled_ciphers,
            m,
            n,
        }
    }

    pub fn is_valid(&self) -> Result<(), Error> {
        if self.input_ciphers.len() != self.shuffled_ciphers.len()
            || self.input_ciphers.len() != self.m * self.n
            || self.shuffled_ciphers.len() != self.m * self.n
        {
            return Err(Error::InvalidShuffleStatement);
        }

        Ok(())
    }
}

/// Witness
pub struct Witness<'a, C: ProjectiveCurve> {
    pub permutation: &'a Permutation,
    pub rho: &'a Vec<C::ScalarField>,
}

impl<'a, C: ProjectiveCurve> Witness<'a, C> {
    pub fn new(permutation: &'a Permutation, rho: &'a Vec<C::ScalarField>) -> Self {
        Self { permutation, rho }
    }
}
