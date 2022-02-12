use ark_crypto_primitives::{
    commitment::{
        pedersen::{Commitment, Randomness, Parameters}, CommitmentScheme,
    },
};

use ark_ec::ProjectiveCurve;
use ark_serialize::{CanonicalSerialize};
use crate::config::ProductArgumentWindow;

pub fn commit<C: ProjectiveCurve>(commit_parameters: &Parameters<C>, x: &Vec<C::ScalarField>, r: &Randomness<C>) -> C::Affine {
    let serialized = x.iter().map(|x| {
        let mut serialized = vec![0; 32];
        x.serialize(&mut serialized[..]).unwrap();
        serialized
    }).collect::<Vec<_>>();

    let serialized = serialized.into_iter().flatten().collect::<Vec<u8>>();

    let commitment = 
        Commitment::<C, ProductArgumentWindow>::commit(commit_parameters, &serialized, r).unwrap();

    commitment
}