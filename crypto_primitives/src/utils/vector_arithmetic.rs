use crate::error::CryptoError;
use ark_ff::Field;
use std::iter::Sum;
use std::ops::Mul;

/// Compute the dot product (inner product) of two vectors
pub fn dot_product<S, T>(scalars: &Vec<S>, rhs: &Vec<T>) -> Result<T, CryptoError>
where
    S: Field,
    T: Copy + Sum<T> + Mul<S, Output = T>,
{
    if scalars.len() != rhs.len() {
        return Err(CryptoError::DotProductLengthError(scalars.len(), rhs.len()));
    }

    Ok(rhs
        .iter()
        .zip(scalars.iter())
        .map(|(&rhs_entry, &scalar_entry)| rhs_entry * scalar_entry)
        .sum())
}

// Compute the Hadamard product (elemet-wise multiplication) of two vectors
pub fn hadamard_product<S: Field>(scalars: &Vec<S>, rhs: &Vec<S>) -> Result<Vec<S>, CryptoError> {
    if scalars.len() != rhs.len() {
        return Err(CryptoError::HadamardProductLengthError(
            scalars.len(),
            rhs.len(),
        ));
    }

    Ok(rhs
        .iter()
        .zip(scalars.iter())
        .map(|(&rhs_entry, &scalar_entry)| rhs_entry.mul(scalar_entry))
        .collect())
}

/// Reshape a vector of length N into a matrix of m-by-n (m chunks of length n). Requires that N = m*n
pub fn reshape<T: Clone>(
    in_vector: &Vec<T>,
    m: usize,
    n: usize,
) -> Result<Vec<Vec<T>>, CryptoError> {
    if in_vector.len() != m * n {
        return Err(CryptoError::VectorCastingError(in_vector.len(), m, n));
    }

    Ok(in_vector.chunks(n).map(|c| c.to_vec()).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::homomorphic_encryption::el_gamal;
    use crate::utils::rand::sample_vector;
    use ark_ff::{One, Zero};
    use ark_std::rand::thread_rng;
    use starknet_curve;

    type Scalar = starknet_curve::Fr;
    type Curve = starknet_curve::Projective;
    type Ciphertext = el_gamal::Ciphertext<Curve>;

    #[test]
    fn dot_product_test() {
        let rng = &mut thread_rng();
        let n = 5;

        let scalars: Vec<Scalar> = sample_vector(rng, n);
        let ciphers: Vec<Ciphertext> = sample_vector(rng, n);

        dot_product(&scalars, &ciphers).unwrap();
    }

    #[test]
    fn hadamard_product_test() {
        let rng = &mut thread_rng();
        let n = 5;

        let scalars: Vec<Scalar> = sample_vector(rng, n);
        let other_scalars: Vec<Scalar> = sample_vector(rng, n);

        hadamard_product(&scalars, &other_scalars).unwrap();

        let zeros = vec![Scalar::zero(); n];
        assert_eq!(zeros, hadamard_product(&zeros, &scalars).unwrap());

        let ones = vec![Scalar::one(); n];
        assert_eq!(scalars, hadamard_product(&ones, &scalars).unwrap());
    }
}
