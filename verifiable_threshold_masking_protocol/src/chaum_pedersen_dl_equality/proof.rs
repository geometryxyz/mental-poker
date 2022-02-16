use crate::chaum_pedersen_dl_equality::{Parameters, error::Error, transcript::TranscriptProtocol};

use ark_ec::{ProjectiveCurve, AffineCurve};
use merlin::Transcript;


pub struct Proof<C> 
where 
    C: ProjectiveCurve
{
    pub(crate) a: C,
    pub(crate) b: C,
    pub(crate) r: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify(&self, parameters: &Parameters<C>, statement: &(C::Affine, C::Affine)) -> Result<(), Error> {
        let mut transcript = Transcript::new(b"chaum_pedersen");

        transcript.append(b"g", &parameters.g);
        transcript.append(b"h", &parameters.h);
        transcript.append(b"x", &statement.0);
        transcript.append(b"y", &statement.1);

        transcript.append(b"a", &self.a);
        transcript.append(b"b", &self.b);


        let c: C::ScalarField = transcript.challenge_scalar(b"c");

        // g * r ==? a + x*c
        if parameters.g.mul(self.r) != self.a + statement.0.mul(c) {
            return Err(Error::VerificationError)
        }


        // h * r ==? b + y*c
        if parameters.h.mul(self.r) != self.b + statement.1.mul(c) {
            return Err(Error::VerificationError)
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    
    use ark_ec::{ProjectiveCurve, AffineCurve};
    use ark_std::{rand::{thread_rng}};
    use ark_std::{UniformRand};
    use starknet_curve::{Projective, Fr};
    use crate::chaum_pedersen_dl_equality::{prover::Prover, Parameters};

    #[test]
    fn test_honest_prover() {
        let mut rng = thread_rng();

        let g = Projective::rand(&mut rng).into_affine();
        let h = Projective::rand(&mut rng).into_affine();

        let parameters = Parameters::<Projective> {
            g, 
            h
        };

        let secret = Fr::rand(&mut rng);
        let statement = (g.mul(secret).into_affine(), h.mul(secret).into_affine());

        let proof = Prover::<Projective>::create_proof(&parameters, &statement, secret);

        assert_eq!(proof.verify(&parameters, &statement), Ok(()));
    }

    #[test]
    fn test_malicious_prover() {
        let mut rng = thread_rng();

        let g = Projective::rand(&mut rng).into_affine();
        let h = Projective::rand(&mut rng).into_affine();

        let parameters = Parameters::<Projective> {
            g, 
            h
        };

        let secret1 = Fr::rand(&mut rng);
        let secret2 = Fr::rand(&mut rng);
        
        let statement = (g.mul(secret1).into_affine(), h.mul(secret2).into_affine());

        let proof = Prover::<Projective>::create_proof(&parameters, &statement, secret1);

        assert_ne!(proof.verify(&parameters, &statement), Ok(()));

    }
}