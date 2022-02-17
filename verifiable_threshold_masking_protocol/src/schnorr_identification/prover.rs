use crate::schnorr_identification::{Parameters, transcript::TranscriptProtocol, proof::Proof};

use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_ff::{PrimeField};
use ark_std::rand::thread_rng;
use ark_std::{UniformRand};
use merlin::Transcript;

use std::marker::PhantomData;



pub struct Prover<C> 
where 
    C: ProjectiveCurve
{
    phantom: PhantomData<C>
}

impl<C> Prover<C> 
where   
    C: ProjectiveCurve
{
    pub fn create_proof(pp: &Parameters<C>, pk: &<C>::Affine, sk: C::ScalarField) -> Proof<C> {
        let mut transcript = Transcript::new(b"schnorr_identity");
        transcript.append(b"public_generator", &pp.generator);
        transcript.append(b"public_key", pk);


        let rng = &mut thread_rng();
        let witness = C::ScalarField::rand(rng);

        let w_commit = pp.generator.mul(witness.into_repr());
        transcript.append(b"witness_commit", &w_commit);

        let c: C::ScalarField = transcript.challenge_scalar(b"c");

        let opening = witness - c * sk;

        let proof = Proof {
            w_commit, 
            opening
        };

        proof
    }
}