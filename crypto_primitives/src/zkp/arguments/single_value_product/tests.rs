#[cfg(test)]

mod test {
    use crate::error::CryptoError;
    use crate::utils::rand::sample_vector;
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use crate::zkp::{arguments::single_value_product, ArgumentOfKnowledge};

    use ark_std::{rand::thread_rng, UniformRand};
    use starknet_curve;
    use std::iter::Iterator;

    // Choose ellitptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Type aliases for concrete instances using the chosen EC.
    type Comm = pedersen::PedersenCommitment<Curve>;
    type Witness<'a> = single_value_product::Witness<'a, Scalar>;
    type Statement<'a> = single_value_product::Statement<'a, Scalar, Comm>;
    type SingleValueProd<'a> = single_value_product::SingleValueProductArgument<'a, Scalar, Comm>;
    type Parameters<'a> = single_value_product::Parameters<'a, Scalar, Comm>;

    #[test]
    fn test_single_product_argument() {
        let n = 13;
        let rng = &mut thread_rng();
        let commit_key = Comm::setup(rng, n);

        let mut a: Vec<Scalar> = sample_vector(rng, n);
        let b: Scalar = a.iter().product();

        let r = Scalar::rand(rng);
        let a_commit = Comm::commit(&commit_key, &a, r).unwrap();

        let parameters = Parameters::new(n, &commit_key);
        let witness = Witness::new(&a, &r);
        let statement = Statement::new(&a_commit, b);

        let valid_proof = SingleValueProd::prove(rng, &parameters, &statement, &witness).unwrap();

        assert_eq!(Ok(()), valid_proof.verify(&parameters, &statement));

        a[0] = a[0] + a[0];
        let bad_witness = Witness::new(&a, &r);
        let invalid_proof =
            SingleValueProd::prove(rng, &parameters, &statement, &bad_witness).unwrap();
        assert_eq!(
            Err(CryptoError::ProofVerificationError(String::from(
                "Single Value Product Argument (5.3)",
            ))),
            SingleValueProd::verify(&parameters, &statement, &invalid_proof)
        );
    }
}
