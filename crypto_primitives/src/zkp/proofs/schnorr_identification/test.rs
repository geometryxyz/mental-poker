#[cfg(test)]
mod test {

    use crate::error::CryptoError;
    use crate::zkp::proofs::schnorr_identification;
    use crate::zkp::proofs::schnorr_identification::SchnorrIdentification;
    use crate::zkp::ArgumentOfKnowledge;
    use ark_ec::AffineCurve;
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;
    use starknet_curve;

    #[test]
    fn test_honest_prover() {
        let mut rng = thread_rng();

        let crs = SchnorrIdentification::<starknet_curve::Projective>::setup(&mut rng).unwrap();

        let secret = starknet_curve::Fr::rand(&mut rng);
        let pk = crs.generator.mul(secret);

        let statement = schnorr_identification::Statement::<starknet_curve::Projective>::new(&pk);
        let witness = schnorr_identification::Witness::<starknet_curve::Projective>::new(&secret);

        let proof =
            SchnorrIdentification::<starknet_curve::Projective>::prove(&crs, &statement, &witness)
                .unwrap();

        assert_eq!(
            SchnorrIdentification::<starknet_curve::Projective>::verify(&crs, &statement, &proof),
            Ok(())
        );
    }

    #[test]
    fn test_malicious_prover() {
        let mut rng = thread_rng();

        let crs = SchnorrIdentification::<starknet_curve::Projective>::setup(&mut rng).unwrap();

        let secret = starknet_curve::Fr::rand(&mut rng);
        let pk = crs.generator.mul(secret);

        let another_scalar = starknet_curve::Fr::rand(&mut rng);

        let statement = schnorr_identification::Statement::<starknet_curve::Projective>::new(&pk);
        let witness =
            schnorr_identification::Witness::<starknet_curve::Projective>::new(&another_scalar);

        let invalid_proof =
            SchnorrIdentification::<starknet_curve::Projective>::prove(&crs, &statement, &witness)
                .unwrap();

        assert_eq!(
            SchnorrIdentification::<starknet_curve::Projective>::verify(
                &crs,
                &statement,
                &invalid_proof
            ),
            Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification"
            )))
        );
    }
}
