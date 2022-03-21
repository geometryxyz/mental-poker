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

    type AffinePoint = starknet_curve::Affine;
    type Curve = starknet_curve::Projective;
    type Parameters<'a> = chaum_pedersen_dl_equality::Parameters<'a, Curve>;

    fn setup<R: Rng>(rng: &mut R) -> (AffinePoint, AffinePoint) {
        (
            Curve::rand(rng).into_affine(),
            Curve::rand(rng).into_affine(),
        )
    }

    #[test]
    fn test_honest_prover() {
        let rng = &mut thread_rng();

        let (g, h) = setup(rng);

        let secret = starknet_curve::Fr::rand(rng);
        let point_a = g.mul(secret).into_affine();
        let point_b = h.mul(secret).into_affine();

        let crs = Parameters::new(&g, &h);
        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );
        let witness = &secret;

        let proof =
            DLEquality::<starknet_curve::Projective>::prove(rng, &crs, &statement, &witness)
                .unwrap();

        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(&crs, &statement, &proof),
            Ok(())
        );

        assert_ne! {point_a, point_b};
    }

    #[test]
    fn test_malicious_prover() {
        let rng = &mut thread_rng();

        let (g, h) = setup(rng);

        let secret = starknet_curve::Fr::rand(rng);
        let point_a = g.mul(secret).into_affine();
        let point_b = h.mul(secret).into_affine();

        let another_scalar = starknet_curve::Fr::rand(rng);

        let crs = Parameters::new(&g, &h);
        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );

        let wrong_witness = &another_scalar;

        let invalid_proof =
            DLEquality::<starknet_curve::Projective>::prove(rng, &crs, &statement, &wrong_witness)
                .unwrap();

        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(&crs, &statement, &invalid_proof),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        );
    }
}
