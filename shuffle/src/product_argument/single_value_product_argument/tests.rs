#[cfg(test)]

mod test {
    use crate::product_argument::single_value_product_argument::{
        prover::Prover, Parameters, Statement, Witness,
    };
    use crate::{
        error::Error,
        utils::{HomomorphicCommitment, PedersenCommitment, RandomSampler, ScalarSampler},
    };
    use ark_ec::ProjectiveCurve;
    use ark_std::rand::thread_rng;
    use rand::Rng;
    use starknet_curve::{Fr, Projective};

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
    fn test_single_product_argument() {
        let n = 52;
        let rng = &mut thread_rng();
        let commit_key = generate_commit_key::<_, Projective>(rng, &n);

        let mut a = ScalarSampler::<Projective>::sample_vector(rng, n);
        let b: Fr = a.iter().product();

        let r = ScalarSampler::<Projective>::sample_element(rng);
        let a_commit = PedersenCommitment::<Projective>::commit_vector(&commit_key, &a, r);

        let parameters = Parameters::<Projective>::new(n, &commit_key);
        let witness = Witness::<Projective>::new(&a, &r);
        let statement = Statement::<Projective>::new(a_commit, b);

        let honest_prover = Prover::<Projective>::new(&parameters, &statement, &witness);
        let valid_proof = honest_prover.prove(rng);

        assert_eq!(Ok(()), valid_proof.verify(&parameters, &statement));

        a[0] = a[0] + a[0];
        let bad_witness = Witness::<Projective>::new(&a, &r);
        let malicious_prover = Prover::new(&parameters, &statement, &bad_witness);
        let invalid_proof = malicious_prover.prove(rng);
        assert_eq!(
            Err(Error::SingleValueProductVerificationError),
            invalid_proof.verify(&parameters, &statement)
        );
    }
}
