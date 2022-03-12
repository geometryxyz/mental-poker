#[cfg(test)]
mod test {
    use crate::utils::rand::RandomSampler;
    use crate::vector_commitment::HomomorphicCommitmentScheme;
    use crate::vector_commitment::{pedersen, pedersen::PedersenCommitment};
    use ark_ff::Zero;
    use ark_std::rand::thread_rng;
    use starknet_curve;

    // Define type aliases for succinctness
    type Curve = starknet_curve::Projective;
    type Scalar = pedersen::Scalar<Curve>;
    type Pedersen = PedersenCommitment<Curve>;

    #[test]
    fn additive_homomorphism() {
        let rng = &mut thread_rng();
        let n = 52;

        let commit_key = Pedersen::setup(rng, n);

        let r1 = RandomSampler::<Scalar>::sample_item(rng);
        let r2 = RandomSampler::<Scalar>::sample_item(rng);

        let v1 = RandomSampler::<Scalar>::sample_vector(rng, n);
        let v2 = RandomSampler::<Scalar>::sample_vector(rng, n);

        let v3 = v1
            .iter()
            .zip(v2.iter())
            .map(|(&a, &b)| a + b)
            .collect::<Vec<_>>();

        let commit_v1 = Pedersen::commit(&commit_key, &v1, r1).unwrap();
        let commit_v2 = Pedersen::commit(&commit_key, &v2, r2).unwrap();
        let commit_v3 = Pedersen::commit(&commit_key, &v3, r1 + r2).unwrap();

        assert_eq!(commit_v1 + commit_v2, commit_v3)
    }

    #[test]
    fn short_commitment() {
        let rng = &mut thread_rng();
        let n = 10;

        let commit_key = Pedersen::setup(rng, n);

        let r = RandomSampler::<Scalar>::sample_item(rng);

        let s1 = RandomSampler::<Scalar>::sample_item(rng);
        let zero = Scalar::zero();

        let v1 = vec![s1, zero, zero, zero];

        let commit_v1 = Pedersen::commit(&commit_key, &v1, r).unwrap();

        let commit_s1 = Pedersen::commit(&commit_key, &vec![s1], r).unwrap();

        assert_eq!(v1[0], s1);
        assert_eq!(commit_v1, commit_s1);
    }

    #[test]
    #[should_panic]
    fn too_many_values() {
        let rng = &mut thread_rng();
        let n = 5;

        let commit_key = Pedersen::setup(rng, n);

        let r = RandomSampler::<Scalar>::sample_item(rng);

        let s1 = RandomSampler::<Scalar>::sample_item(rng);

        let too_long = vec![s1; n + 2];

        let _commit = Pedersen::commit(&commit_key, &too_long, r).unwrap();
    }
}
