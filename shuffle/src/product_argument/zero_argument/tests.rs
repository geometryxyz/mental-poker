#[cfg(test)]
mod test {
    use crate::product_argument::zero_argument::{
        prover::Prover, Parameters, Statement, Witness, YMapping,
    };
    use crate::{
        error::Error,
        utils::{HomomorphicCommitment, PedersenCommitment, RandomSampler, ScalarSampler},
    };
    use ark_ec::ProjectiveCurve;
    use ark_ff::Zero;
    use ark_std::rand::thread_rng;
    use rand::Rng;
    use starknet_curve::{Fr, Projective};
    use std::iter::Iterator;

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
    fn test_zero_argument() {
        // i=1: map(a_1, b_0) = a_1[0]b_0[0]y + a_1[1]b_0[1]y^2 + a_1[2]b_0[2]y^3 + ... + a_1[n-1]b_0[n-1]y^n
        // i=2: map(a_2, b_1) = a_2[0]b_1[0]y + a_2[1]b_1[1]y^2 + a_2[2]b_1[2]y^3 + ... + a_2[n-1]b_1[n-1]y^n
        // i=3: map(a_3, b_2) = a_3[0]b_2[0]y + a_3[1]b_2[1]y^2 + a_3[2]b_2[2]y^3 + ... + a_3[n-1]b_2[n-1]y^n
        // ...
        // i=m: map(a_m, b_{m-1}) = a_m[0]b_{m-1}[0]y + a_m[1]b_{m-1}[1]y^2 + a_m[2]b_{m-1}[2]y^3 + ... + a_m[n-1]b_{m-1}[n-1]y^n

        let m = 4;
        let n = 13;

        let rng = &mut thread_rng();

        let commit_key = generate_commit_key::<_, Projective>(rng, &n);

        let random_scalars = ScalarSampler::<Projective>::sample_vector(rng, m * n);
        let a_chunks = random_scalars
            .chunks(n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let r = ScalarSampler::<Projective>::sample_vector(rng, a_chunks.len());
        let a_commits = a_chunks
            .iter()
            .zip(r.iter())
            .map(|(a_chunk, &random)| {
                PedersenCommitment::commit_vector(&commit_key, a_chunk, random)
            })
            .collect::<Vec<Projective>>();

        let zeros = vec![Fr::zero(); m * n];
        let b_chunks = zeros.chunks(n).map(|c| c.to_vec()).collect::<Vec<_>>();

        let s = ScalarSampler::<Projective>::sample_vector(rng, a_chunks.len());
        let b_commits = b_chunks
            .iter()
            .zip(s.iter())
            .map(|(b_chunk, &random)| {
                PedersenCommitment::commit_vector(&commit_key, b_chunk, random)
            })
            .collect::<Vec<Projective>>();

        let proof_parameters = Parameters::new(m, n, &commit_key);

        let y = ScalarSampler::<Projective>::sample_element(rng);
        let test_mapping = YMapping::<Projective>::new(y, n);

        let statement = Statement {
            commitment_to_a: &a_commits,
            commitment_to_b: &b_commits,
            bilinear_map: &test_mapping,
        };

        let valid_witness = Witness::new(&a_chunks, &r, &b_chunks, &s);

        let honest_prover = Prover::new(&proof_parameters, &statement, &valid_witness);

        let valid_proof = honest_prover.prove(rng);

        assert_eq!(Ok(()), valid_proof.verify(&proof_parameters, &statement));

        let bad_witness = Witness::<Projective>::new(&a_chunks, &r, &a_chunks, &r);

        let malicious_prover = Prover::new(&proof_parameters, &statement, &bad_witness);

        let invalid_proof = malicious_prover.prove(rng);

        assert_eq!(
            Err(Error::ZeroArgumentVerificationError),
            invalid_proof.verify(&proof_parameters, &statement)
        );
    }
}
