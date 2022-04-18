#[cfg(test)]

mod test {
    use crate::utils::rand::sample_vector;
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use crate::zkp::{arguments::matrix_elements_product, ArgumentOfKnowledge};

    use ark_ff::One;
    use ark_std::{rand::thread_rng, UniformRand};
    use starknet_curve;
    use std::iter::Iterator;

    // Choose ellitptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Type aliases for concrete instances using the chosen EC.
    type Comm = pedersen::PedersenCommitment<Curve>;
    type Witness<'a> = matrix_elements_product::Witness<'a, Scalar>;
    type Statement<'a> = matrix_elements_product::Statement<'a, Scalar, Comm>;
    type ProductArgument<'a> = matrix_elements_product::ProductArgument<'a, Scalar, Comm>;
    type Parameters<'a> = matrix_elements_product::Parameters<'a, Scalar, Comm>;

    #[test]
    fn test_complete_product_argument() {
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

        let raw_prod = random_scalars.iter().fold(Scalar::one(), |x, y| x * y);

        let proof_parameters = Parameters::new(m, n, &commit_key);
        let statement = Statement::new(&a_commits, raw_prod);

        let valid_witness = Witness::new(&a_chunks, &r);

        // let honest_prover = Prover::new(&proof_parameters, &statement, &valid_witness);
        // let valid_proof = honest_prover.prove(rng);

        let valid_proof =
            ProductArgument::prove(rng, &proof_parameters, &statement, &valid_witness).unwrap();

        assert_eq!(Ok(()), valid_proof.verify(&proof_parameters, &statement));

        let new_random_scalars: Vec<Scalar> = sample_vector(rng, m * n);
        let bad_a_chunks = new_random_scalars
            .chunks(n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let bad_r: Vec<Scalar> = sample_vector(rng, a_chunks.len());
        let bad_a_commits = a_chunks
            .iter()
            .zip(bad_r.iter())
            .map(|(a_chunk, &random)| Comm::commit(&commit_key, a_chunk, random).unwrap())
            .collect::<Vec<_>>();

        let statement = Statement::new(&bad_a_commits, raw_prod);

        let invalid_witness = Witness::new(&bad_a_chunks, &r);
        let invalid_proof =
            ProductArgument::prove(rng, &proof_parameters, &statement, &invalid_witness).unwrap();

        assert_ne!(Ok(()), invalid_proof.verify(&proof_parameters, &statement));

        let fake_product = Scalar::rand(rng);

        let wrong_statement = Statement::new(&a_commits, fake_product);

        let invalid_witness = Witness::new(&a_chunks, &r);

        let invalid_proof =
            ProductArgument::prove(rng, &proof_parameters, &wrong_statement, &invalid_witness)
                .unwrap();

        assert_ne!(
            Ok(()),
            invalid_proof.verify(&proof_parameters, &wrong_statement)
        );
    }
}
