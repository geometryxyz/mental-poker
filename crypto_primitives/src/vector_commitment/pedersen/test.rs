#[cfg(test)]
mod test {
    use super::super::*;
    use crate::utils::{rand, rand::RandomSampler};
    use ark_ff::Zero;
    use ark_std::{rand::thread_rng, UniformRand};
    use starknet_curve;

    #[test]
    fn additive_homomorphism() {
        let rng = &mut thread_rng();
        let n = 52;

        let commit_key = PedersenCommitment::<starknet_curve::Projective>::setup(rng, n);

        let r1 = starknet_curve::Fr::rand(rng);
        let r2 = starknet_curve::Fr::rand(rng);

        let v1 = rand::ScalarSampler::<starknet_curve::Projective>::sample_vector(rng, n);
        let v2 = rand::ScalarSampler::<starknet_curve::Projective>::sample_vector(rng, n);

        let v3 = v1.iter().zip(v2.iter()).map(|(&a, &b)| a + b).collect::<Vec<_>>();

        let commit_v1 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v1.from_field(), r1).unwrap();
        let commit_v2 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v2, r2).unwrap();
        let commit_v3 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v3, r1 + r2)
                .unwrap();

        assert_eq!(commit_v1 + commit_v2, commit_v3)
    }

    #[test]
    fn short_commitment() {
        let rng = &mut thread_rng();
        let n = 10;

        let commit_key = PedersenCommitment::<starknet_curve::Projective>::setup(rng, n);

        let r = starknet_curve::Fr::rand(rng);

        let s1 = starknet_curve::Fr::rand(rng);
        let zero = starknet_curve::Fr::zero();

        let v1 = vec![s1, zero, zero, zero];

        let commit_v1 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v1, r).unwrap();

        let commit_s1 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &vec![s1], r)
                .unwrap();

        assert_eq!(v1[0], s1);
        assert_eq!(commit_v1, commit_s1);
    }

    #[test]
    #[should_panic]
    fn too_many_values() {
        let rng = &mut thread_rng();
        let n = 5;

        let commit_key = PedersenCommitment::<starknet_curve::Projective>::setup(rng, n);

        let r = starknet_curve::Fr::rand(rng);

        let s1 = starknet_curve::Fr::rand(rng);

        let too_long = vec![s1; n + 2];

        let _commit =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &too_long, r)
                .unwrap();
    }
}
