#[cfg(test)]

mod test {

    use crate::error::CryptoError;
    use crate::utils::rand::sample_vector;
    use crate::utils::vector_arithmetic::hadamard_product;
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use crate::zkp::{arguments::hadamard_product, ArgumentOfKnowledge};

    use ark_ff::One;
    use ark_std::{rand::thread_rng, UniformRand};
    use starknet_curve;
    use std::iter::Iterator;

    // Choose ellitptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Type aliases for concrete instances using the chosen EC.
    type Comm = pedersen::PedersenCommitment<Curve>;
    type Witness<'a> = hadamard_product::Witness<'a, Scalar>;
    type Statement<'a> = hadamard_product::Statement<'a, Scalar, Comm>;
    type HadamardProductArgument<'a> = hadamard_product::HadamardProductArgument<'a, Scalar, Comm>;
    type Parameters<'a> = hadamard_product::Parameters<'a, Scalar, Comm>;

    #[test]
    fn test_hadamard_product_argument() {
        let m = 4;
        let n = 13;

        let rng = &mut thread_rng();
        let commit_key = Comm::setup(rng, n);

        let random_scalars: Vec<Scalar> = sample_vector(rng, m * n);
        let a_chunks = random_scalars
            .chunks(n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let r: Vec<Scalar> = sample_vector(rng, a_chunks.len());
        let a_commits = a_chunks
            .iter()
            .zip(r.iter())
            .map(|(a_chunk, &random)| Comm::commit(&commit_key, a_chunk, random).unwrap())
            .collect::<Vec<_>>();

        let b = a_chunks.iter().fold(vec![Scalar::one(); n], |x, y| {
            hadamard_product(&x, &y).unwrap()
        });

        let product = b.iter().fold(Scalar::one(), |x, y| x * y);

        let raw_prod = random_scalars.iter().fold(Scalar::one(), |x, y| x * y);

        assert_eq!(product, raw_prod);

        let s = Scalar::rand(rng);
        let b_commit = Comm::commit(&commit_key, &b, s).unwrap();

        let proof_parameters = Parameters::new(m, n, &commit_key);
        let statement = Statement::new(&a_commits, b_commit);

        let valid_witness = Witness::new(&a_chunks, &r, &b, s);

        let valid_proof =
            HadamardProductArgument::prove(rng, &proof_parameters, &statement, &valid_witness)
                .unwrap();

        assert_eq!(
            Ok(()),
            HadamardProductArgument::verify(&proof_parameters, &statement, &valid_proof)
        );

        let bad_b: Vec<Scalar> = sample_vector(rng, n);
        let invalid_witness = Witness::new(&a_chunks, &r, &bad_b, s);
        let invalid_proof =
            HadamardProductArgument::prove(rng, &proof_parameters, &statement, &invalid_witness)
                .unwrap();

        assert_eq!(
            Err(CryptoError::ProofVerificationError(String::from(
                "Hadamard Product (5.1)",
            ))),
            HadamardProductArgument::verify(&proof_parameters, &statement, &invalid_proof)
        );
    }
}
