use super::{proof::Proof, Parameters, Statement, Witness};

use crate::zkp::transcript::TranscriptProtocol;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use merlin::Transcript;

use std::marker::PhantomData;

pub struct Prover<C>
where
    C: ProjectiveCurve,
{
    phantom: PhantomData<C>,
}

impl<C> Prover<C>
where
    C: ProjectiveCurve,
{
    pub fn create_proof<R: Rng>(
        rng: &mut R,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
    ) -> Proof<C> {
        let mut transcript = Transcript::new(b"schnorr_identity");
        transcript.append(b"public_generator", pp);
        transcript.append(b"public_key", statement);

        let random = C::ScalarField::rand(rng);

        let random_commit = pp.mul(random.into_repr());
        transcript.append(b"witness_commit", &random_commit);

        let c: C::ScalarField = transcript.challenge_scalar(b"c");

        let opening = random - c * witness;

        Proof {
            random_commit,
            opening,
        }
    }
}
