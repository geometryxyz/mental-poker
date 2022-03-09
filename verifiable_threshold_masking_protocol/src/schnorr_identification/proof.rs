use crate::schnorr_identification::{error::Error, transcript::TranscriptProtocol, Parameters};
use ark_ff::PrimeField;

use ark_ec::{AffineCurve, ProjectiveCurve};
use merlin::Transcript;

pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub(crate) w_commit: C,
    pub(crate) opening: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify(&self, pp: &Parameters<C>, pk: &C::Affine) -> Result<(), Error> {
        let mut transcript = Transcript::new(b"schnorr_identity");

        transcript.append(b"public_generator", &pp.generator);
        transcript.append(b"public_key", pk);
        transcript.append(b"witness_commit", &self.w_commit);

        let c: C::ScalarField = transcript.challenge_scalar(b"c");

        if pp.generator.mul(self.opening.into_repr()) + pk.mul(c.into_repr()) != self.w_commit {
            return Err(Error::VerificationError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::schnorr_identification::{prover::Prover, Parameters};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;
    use starknet_curve::{Fr, Projective};

    #[test]
    fn test_honest_prover() {
        let mut rng = thread_rng();

        let generator = Projective::rand(&mut rng).into_affine();

        let parameters = Parameters::<Projective> { generator };

        let secret = Fr::rand(&mut rng);
        let pk = generator.mul(secret).into_affine();

        let proof = Prover::<Projective>::create_proof(&parameters, &pk.into(), secret);

        assert_eq!(proof.verify(&parameters, &pk.into()), Ok(()));
    }

    #[test]
    fn test_malicious_prover() {
        let mut rng = thread_rng();

        let generator = Projective::rand(&mut rng).into_affine();

        let parameters = Parameters::<Projective> { generator };

        let secret = Fr::rand(&mut rng);
        let statement = generator.mul(secret).into_affine();

        let another_scalar = Fr::rand(&mut rng);
        let proof =
            Prover::<Projective>::create_proof(&parameters, &statement.into(), another_scalar);

        assert_ne!(proof.verify(&parameters, &statement.into()), Ok(()));
    }
}
