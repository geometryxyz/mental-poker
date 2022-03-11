pub mod hadamard_product;
pub mod multi_exponentiation;
pub mod shuffle;
pub mod single_value_product;
pub mod zero_value_bilinear_map;

use ark_ff::{Field, One};
use std::iter;

pub fn scalar_powers<F: Field>(x: F, n: usize) -> Vec<F> {
    iter::once(F::one())
        .chain(iter::once(x))
        .chain((1..n).scan(x, |current_power, _exp| {
            *current_power *= x;
            Some(*current_power)
        }))
        .collect::<Vec<_>>()
}
