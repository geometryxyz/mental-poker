use ark_ec::ProjectiveCurve;
use merlin::Transcript;
use crate::product_argument::{
    proof::Proof,
};
use crate::config::PublicConfig;

pub struct Verifier<C, const SIZE: usize>
where 
    C: ProjectiveCurve 
{
    transcript: Transcript,
    config: PublicConfig<C>,
    //TODO this is just temorary here
    b: C::ScalarField
}

impl<C, const SIZE: usize> Verifier<C, SIZE>
where
    C: ProjectiveCurve 
{
    pub fn new(label: &'static [u8], config: PublicConfig<C>, b: C::ScalarField) -> Self {
        Self {
            transcript: Transcript::new(label),
            config,
            b
        }
    }

    //TODO start implementing errors and this function should return Result<(), Error>
    pub fn verify(
        &self,
        proof: &Proof<C, SIZE>,
    ) {
        proof.verify(
            self.config.clone(), 
            self.b,
            &mut self.transcript.clone(),
        );
    }
}
