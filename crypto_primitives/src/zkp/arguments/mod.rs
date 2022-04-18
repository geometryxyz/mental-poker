pub mod hadamard_product;
pub mod matrix_elements_product;
pub mod multi_exponentiation;
pub mod shuffle;
pub mod single_value_product;
pub mod zero_value_bilinear_map;

use ark_ff::Field;
use std::iter;

/// Compute the powers of a given scalar $x$ from $x^0$ to $x^(n)$ (included)
pub fn scalar_powers<F: Field>(x: F, n: usize) -> Vec<F> {
    iter::once(F::one())
        .chain(iter::once(x))
        .chain((1..n).scan(x, |current_power, _exp| {
            *current_power *= x;
            Some(*current_power)
        }))
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod scalar_power_test {
    use super::scalar_powers;
    use starknet_curve::Fr;

    #[test]
    fn nth_power() {
        let two = Fr::from(2u64);
        let n = 1;

        let expected = (0..=n)
            .map(|i| {
                let integer: u64 = 1 << i;
                Fr::from(integer)
            })
            .collect::<Vec<_>>();

        let powers = scalar_powers(two, n);
        assert_eq!(powers, expected);
        assert_eq!(powers.len(), n + 1);
    }
}
