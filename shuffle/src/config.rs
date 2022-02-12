use ark_ec::ProjectiveCurve;

use ark_crypto_primitives::{
    commitment::{
        pedersen::{Commitment, Parameters}, CommitmentScheme
    },
    crh::pedersen,
};
use ark_std::rand::prelude::StdRng;

const BITS_PER_SCALAR: usize = 256; 
const NUM_OF_SCALARS: usize = 10;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProductArgumentWindow;

impl pedersen::Window for ProductArgumentWindow {
    const WINDOW_SIZE: usize = BITS_PER_SCALAR;
    const NUM_WINDOWS: usize = NUM_OF_SCALARS;
}

#[derive(Clone)]
pub struct PublicConfig<C>
where
    C: ProjectiveCurve
{
    pub parameters: Parameters<C>
}

impl<C> PublicConfig<C> 
where
    C: ProjectiveCurve
{
    pub fn new(public_randomness: &mut StdRng) -> Self {
        let parameters = Commitment::<C, ProductArgumentWindow>::setup(public_randomness).unwrap();

        PublicConfig {
            parameters
        }
    }
}