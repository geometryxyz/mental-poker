use super::{Statement, Parameters, Witness};

use crate::{
    error::Error,
    utils::{
        ScalarSampler, RandomSampler, PedersenCommitment, HomomorphicCommitment, DotProduct, DotProductCalculator, HadamardProduct, HadamardProductCalculator}, 
    transcript::TranscriptProtocol
};

use ark_ec::{ProjectiveCurve};
use ark_ff::{Zero, One};
use merlin::Transcript;
use rand::Rng;
use std::iter;

pub struct Prover<'a, C>
where 
    C: ProjectiveCurve,
{
    parameters: &'a Parameters<'a, C>,
    transcript: Transcript,
    statement: &'a Statement<'a, C>,
    witness: &'a Witness<'a, C>, 
}

impl<'a, C: ProjectiveCurve> Prover<'a, C> {
    pub fn new(
        parameters: &'a Parameters<'a, C>,
        statement: &'a Statement<'a, C>,
        witness: &'a Witness<'a, C>
    ) -> Self {

        Self {
            parameters, 
            transcript: Transcript::new(b"hadamard_product_argument"),
            statement, 
            witness
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) {
        let mut transcript = self.transcript.clone();

        let mut acc = vec![C::ScalarField::one(); self.parameters.n];

        let b = self.witness.matrix_a.iter().map(|x| {
            acc = acc.iter().zip(x.iter()).map(|(&s_a, &s_b)| s_a * s_b).collect();
            acc.clone()
        }).collect::<Vec<_>>();

    }
}