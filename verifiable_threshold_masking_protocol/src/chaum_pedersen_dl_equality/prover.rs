use crate::chaum_pedersen_dl_equality::{proof::Proof, transcript::TranscriptProtocol, Parameters};
use crate::discrete_log_vtmp::ElgamalCipher;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::rand::thread_rng;
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
    pub fn create_proof(
        parameters: &Parameters<C>,
        statement: &ElgamalCipher<C>,
        secret: C::ScalarField,
    ) -> Proof<C> {
        let mut transcript = Transcript::new(b"chaum_pedersen");
        transcript.append(b"g", &parameters.g);
        transcript.append(b"h", &parameters.h);
        transcript.append(b"x", &statement.0);
        transcript.append(b"y", &statement.1);

        let rng = &mut thread_rng();

        let omega = C::ScalarField::rand(rng);
        let a = parameters.g.mul(omega.into_repr());
        let b = parameters.h.mul(omega.into_repr());

        transcript.append(b"a", &a);
        transcript.append(b"b", &b);

        let c: C::ScalarField = transcript.challenge_scalar(b"c");

        let r = omega + c * secret;

        Proof { a, b, r }
    }
}
