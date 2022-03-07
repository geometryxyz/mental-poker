pub mod config;
pub mod utils;
pub mod error;
pub mod transcript;
pub mod tests;

pub mod prover;
pub mod proof;

pub mod multi_exponent_argument;
pub mod product_argument;

use ark_ec::{ProjectiveCurve};
use verifiable_threshold_masking_protocol::discrete_log_vtmp::{ElgamalCipher};
use rand::{Rng, seq::SliceRandom};


pub struct Permutation {
    pub mapping: Vec<usize>,
    pub size: usize
}

impl Permutation {
    pub fn new<R: Rng>(rng: &mut R, size: usize) -> Self {
        let mut mapping: Vec<usize> = Vec::with_capacity(size);
        for i in 0..size {
            mapping.push(i);
        }
        mapping.shuffle(rng);
        Self {
            mapping, 
            size
        }
    }

    pub fn from(permutation_vec: &Vec<usize>) -> Self {
        Self {
            mapping: permutation_vec[..].to_vec(),
            size: permutation_vec.len()
        }
    }

    pub fn identity(size: usize) -> Self {
        Self {
            mapping: (0..size).collect(),
            size: size
        }
    }

    pub fn permute_array<T: Copy>(&self, input_vector: &Vec<T>) -> Vec<T> {
        self.mapping.iter().map(|&pi_i| {
            input_vector[pi_i]
        }).collect::<Vec<T>>()
    }
}


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

/// Statement of a shuffle. Contains the input ciphertexts, the output ciphertexts and the matric dimensions
pub struct Statement<'a, C: ProjectiveCurve> {
    pub input_ciphers: &'a Vec<ElgamalCipher<C>>,
    pub shuffled_ciphers: &'a Vec<ElgamalCipher<C>>,
    pub m: usize,
    pub n: usize,
}

impl<'a, C: ProjectiveCurve> Statement<'a, C> {
    pub fn new(input_ciphers: &'a Vec<ElgamalCipher<C>>, shuffled_ciphers: &'a Vec<ElgamalCipher<C>>, m: usize, n: usize) -> Self {
        Self {
            input_ciphers, 
            shuffled_ciphers,
            m,
            n
        }
    }
}

/// Witness
pub struct Witness<'a, C: ProjectiveCurve> {
    pub permutation: &'a Permutation,
    pub rho: &'a Vec<C::ScalarField>,
    }

    impl<'a, C: ProjectiveCurve> Witness<'a, C> {
    pub fn new(permutation: &'a Permutation, rho: &'a Vec<C::ScalarField>) -> Self {
        Self {
            permutation,
            rho
        }
    }
}
