#[cfg(test)]
mod test {

    use crate::error::CryptoError;
    use crate::zkp::proofs::chaum_pedersen_dl_equality;
    use crate::zkp::proofs::chaum_pedersen_dl_equality::DLEquality;
    use crate::zkp::ArgumentOfKnowledge;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;
    use starknet_curve;

    #[test]
    fn test_honest_prover() {
        let mut rng = thread_rng();

        let crs = DLEquality::<starknet_curve::Projective>::setup(&mut rng).unwrap();

        let secret = starknet_curve::Fr::rand(&mut rng);
        let point_a = crs.g.mul(secret).into_affine();
        let point_b = crs.h.mul(secret).into_affine();

        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );
        let witness =
            chaum_pedersen_dl_equality::Witness::<starknet_curve::Projective>::new(&secret);

        let proof =
            DLEquality::<starknet_curve::Projective>::prove(&crs, &statement, &witness).unwrap();

        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(&crs, &statement, &proof),
            Ok(())
        );
    }

    #[test]
    fn test_malicious_prover() {
        let mut rng = thread_rng();

        let crs = DLEquality::<starknet_curve::Projective>::setup(&mut rng).unwrap();

        let secret = starknet_curve::Fr::rand(&mut rng);
        let point_a = crs.g.mul(secret).into_affine();
        let point_b = crs.h.mul(secret).into_affine();

        let another_scalar = starknet_curve::Fr::rand(&mut rng);

        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );
        let witness =
            chaum_pedersen_dl_equality::Witness::<starknet_curve::Projective>::new(&another_scalar);

        let invalid_proof =
            DLEquality::<starknet_curve::Projective>::prove(&crs, &statement, &witness).unwrap();

        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(&crs, &statement, &invalid_proof),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        );
    }

    #[test]
    fn test_custom_parameters() {
        let mut rng = thread_rng();
        let generator = starknet_curve::Projective::rand(&mut rng).into_affine();

        let sk = starknet_curve::Fr::rand(&mut rng);
        let pk = generator.mul(sk).into_affine();

        let crs = chaum_pedersen_dl_equality::Parameters::<starknet_curve::Projective>::new(
            generator, pk,
        );

        let secret_masking_factor = starknet_curve::Fr::rand(&mut rng);
        let point_a = crs.g.mul(secret_masking_factor).into_affine();
        let point_b = crs.h.mul(secret_masking_factor).into_affine();

        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );
        let witness = chaum_pedersen_dl_equality::Witness::<starknet_curve::Projective>::new(
            &secret_masking_factor,
        );

        let proof =
            DLEquality::<starknet_curve::Projective>::prove(&crs, &statement, &witness).unwrap();

        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(&crs, &statement, &proof),
            Ok(())
        );
    }
}
