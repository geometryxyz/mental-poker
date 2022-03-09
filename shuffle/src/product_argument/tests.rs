#[cfg(test)]

mod test {

    use crate::product_argument::{prover::Prover, Parameters, Statement, Witness};
    use crate::utils::{HomomorphicCommitment, PedersenCommitment, RandomSampler, ScalarSampler};
    use ark_ec::ProjectiveCurve;
    use ark_ff::One;
    use ark_std::rand::thread_rng;
    use rand::Rng;
    use starknet_curve;

    fn generate_commit_key<R: Rng, C: ProjectiveCurve>(
        public_randomess: &mut R,
        len: &usize,
    ) -> Vec<C::Affine> {
        let mut commit_key = Vec::with_capacity(len + 1);
        let mut base = C::rand(public_randomess);
        for _ in 0..len + 1 {
            commit_key.push(base.into_affine());
            base.double_in_place();
        }
        commit_key
    }

    #[test]
    fn test_complete_product_argument() {
        let m = 4;
        let n = 13;

        let rng = &mut thread_rng();

        let commit_key = generate_commit_key::<_, starknet_curve::Projective>(rng, &n);

        let random_scalars = ScalarSampler::<starknet_curve::Projective>::sample_vector(rng, m * n);
        let a_chunks = random_scalars
            .chunks(n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let r = ScalarSampler::<starknet_curve::Projective>::sample_vector(rng, a_chunks.len());
        let a_commits = a_chunks
            .iter()
            .zip(r.iter())
            .map(|(a_chunk, &random)| {
                PedersenCommitment::commit_vector(&commit_key, a_chunk, random)
            })
            .collect::<Vec<starknet_curve::Projective>>();

        let raw_prod = random_scalars
            .iter()
            .fold(starknet_curve::Fr::one(), |x, y| x * y);

        let proof_parameters = Parameters::<starknet_curve::Projective>::new(m, n, &commit_key);
        let statement = Statement::new(&a_commits, raw_prod);

        let valid_witness = Witness::<starknet_curve::Projective>::new(&a_chunks, &r);
        let honest_prover = Prover::new(&proof_parameters, &statement, &valid_witness);
        let valid_proof = honest_prover.prove(rng);

        assert_eq!(Ok(()), valid_proof.verify(&proof_parameters, &statement));

        let new_random_scalars =
            ScalarSampler::<starknet_curve::Projective>::sample_vector(rng, m * n);
        let bad_a_chunks = new_random_scalars
            .chunks(n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let bad_r = ScalarSampler::<starknet_curve::Projective>::sample_vector(rng, a_chunks.len());
        let bad_a_commits = a_chunks
            .iter()
            .zip(bad_r.iter())
            .map(|(a_chunk, &random)| {
                PedersenCommitment::commit_vector(&commit_key, a_chunk, random)
            })
            .collect::<Vec<starknet_curve::Projective>>();

        let statement = Statement::new(&bad_a_commits, raw_prod);

        let invalid_witness = Witness::<starknet_curve::Projective>::new(&bad_a_chunks, &r);
        let malicious_prover = Prover::new(&proof_parameters, &statement, &invalid_witness);
        let invalid_proof = malicious_prover.prove(rng);

        assert_ne!(Ok(()), invalid_proof.verify(&proof_parameters, &statement));

        let fake_product = ScalarSampler::<starknet_curve::Projective>::sample_element(rng);

        let wrong_statement = Statement::new(&a_commits, fake_product);

        let invalid_witness = Witness::<starknet_curve::Projective>::new(&a_chunks, &r);
        let malicious_prover = Prover::new(&proof_parameters, &wrong_statement, &invalid_witness);
        let invalid_proof = malicious_prover.prove(rng);

        assert_ne!(
            Ok(()),
            invalid_proof.verify(&proof_parameters, &wrong_statement)
        );
    }
}
