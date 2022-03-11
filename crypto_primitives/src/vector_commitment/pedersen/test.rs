#[cfg(test)]
mod test {
    use super::super::*;
    use crate::error::CryptoError;
    use ark_ff::Zero;
    use ark_std::{rand::thread_rng, UniformRand};
    use starknet_curve;

    #[test]
    fn test_sum_commitments() {
        let rng = &mut thread_rng();
        let n = 2;

        let commit_key = PedersenCommitment::<starknet_curve::Projective>::setup(rng, n);

        let r1 = starknet_curve::Fr::rand(rng);
        let r2 = starknet_curve::Fr::rand(rng);

        let s1 = starknet_curve::Fr::rand(rng);
        let s2 = starknet_curve::Fr::rand(rng);
        let s3 = starknet_curve::Fr::rand(rng);

        let v1 = vec![s1, s2];
        let v2 = vec![s3];

        let sum = s1 + s3;

        let v3 = vec![sum, s2];

        let commit_v1 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v1, r1).unwrap();
        let commit_v2 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v2, r2).unwrap();
        let commit_v3 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v3, r1 + r2)
                .unwrap();

        assert_eq!(commit_v1 + commit_v2, commit_v3)
    }

    #[test]
    fn test_short_commitment() {
        let rng = &mut thread_rng();
        let n = 2;

        let commit_key = PedersenCommitment::<starknet_curve::Projective>::setup(rng, n);

        let r = starknet_curve::Fr::rand(rng);

        let s1 = starknet_curve::Fr::rand(rng);
        let zero = starknet_curve::Fr::zero();

        let v1 = vec![s1];
        let v2 = vec![s1, zero];

        let commit_v1 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v1, r).unwrap();

        let commit_v2 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &v2, r).unwrap();

        let commit_s1 =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &vec![s1], r)
                .unwrap();

        assert_eq!(v1[0], s1);
        assert_eq!(commit_v1, commit_s1);

        assert_eq!(commit_v1, commit_v2)
    }

    #[test]
    fn too_many_values() {
        let rng = &mut thread_rng();
        let n = 5;

        let commit_key = PedersenCommitment::<starknet_curve::Projective>::setup(rng, n);

        let r = starknet_curve::Fr::rand(rng);

        let s1 = starknet_curve::Fr::rand(rng);

        let too_long = vec![s1; n + 2];

        let commit =
            PedersenCommitment::<starknet_curve::Projective>::commit(&commit_key, &too_long, r);

        assert_eq!(
            commit,
            Err(CryptoError::CommitmentLengthError(
                String::from("Pedersen"),
                too_long.len(),
                commit_key.g.len()
            ))
        )
    }
}
