#[cfg(test)]
mod test {

    use crate::error::CryptoError;
    use crate::zkp::proofs::chaum_pedersen_dl_equality;
    use crate::zkp::proofs::chaum_pedersen_dl_equality::DLEquality;
    use crate::zkp::ArgumentOfKnowledge;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use starknet_curve;

    type Curve = starknet_curve::Projective;
    type Parameters = chaum_pedersen_dl_equality::Parameters<Curve>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Parameters, CryptoError> {
        let generator1 = Curve::rand(rng).into_affine();
        let generator2 = Curve::rand(rng).into_affine();
        let parameters = Parameters::new(generator1, generator2);

        Ok(parameters)
    }

    #[test]
    fn test_honest_prover() {
        let mut rng = thread_rng();

        let crs = setup(&mut rng).unwrap();

        let secret = starknet_curve::Fr::rand(&mut rng);
        let point_a = crs.g.mul(secret).into_affine();
        let point_b = crs.h.mul(secret).into_affine();

        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );

        let proof =
            DLEquality::<starknet_curve::Projective>::prove(&crs, &statement, &secret).unwrap();

        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(&crs, &statement, &proof),
            Ok(())
        );
    }

    #[test]
    fn test_malicious_prover() {
        let mut rng = thread_rng();

        let crs = setup(&mut rng).unwrap();

        let secret = starknet_curve::Fr::rand(&mut rng);
        let point_a = crs.g.mul(secret).into_affine();
        let point_b = crs.h.mul(secret).into_affine();

        let another_scalar = starknet_curve::Fr::rand(&mut rng);

        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );

        let invalid_proof =
            DLEquality::<starknet_curve::Projective>::prove(&crs, &statement, &another_scalar)
                .unwrap();

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

        let proof = DLEquality::<starknet_curve::Projective>::prove(
            &crs,
            &statement,
            &secret_masking_factor,
        )
        .unwrap();

        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(&crs, &statement, &proof),
            Ok(())
        );
    }
}
