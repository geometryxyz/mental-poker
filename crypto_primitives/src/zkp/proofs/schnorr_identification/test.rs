#[cfg(test)]
mod test {

    use crate::error::CryptoError;
    use crate::zkp::{proofs::schnorr_identification, ArgumentOfKnowledge};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;
    use rand::Rng;
    use starknet_curve;

    type Curve = starknet_curve::Projective;
    type Schnorr<'a> = schnorr_identification::SchnorrIdentification<Curve>;
    type Scalar = starknet_curve::Fr;
    type Parameters = schnorr_identification::Parameters<Curve>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Parameters, CryptoError> {
        Ok(Curve::rand(rng).into_affine())
    }

    #[test]
    fn test_honest_prover() {
        let mut rng = thread_rng();

        let crs = setup(&mut rng).unwrap();

        let secret = Scalar::rand(&mut rng);
        let pk = crs.mul(secret).into_affine();

        let proof = Schnorr::prove(&mut rng, &crs, &pk, &secret).unwrap();

        assert_eq!(Schnorr::verify(&crs, &pk, &proof), Ok(()));
    }

    #[test]
    fn test_malicious_prover() {
        let mut rng = thread_rng();

        let crs = setup(&mut rng).unwrap();

        let secret = Scalar::rand(&mut rng);
        let pk = crs.mul(secret).into_affine();

        let another_scalar = Scalar::rand(&mut rng);

        let invalid_proof = Schnorr::prove(&mut rng, &crs, &pk, &another_scalar).unwrap();

        assert_eq!(
            Schnorr::verify(&crs, &pk, &invalid_proof),
            Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification"
            )))
        );
    }
}
