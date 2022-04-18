#[cfg(test)]
mod test {
    use crate::utils::rand::sample_vector;
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use ark_ff::Zero;
    use ark_std::{rand::thread_rng, UniformRand};
    use starknet_curve;
    use std::ops::Mul;

    // Define type aliases for succinctness
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;
    type Pedersen = pedersen::PedersenCommitment<Curve>;

    #[test]
    fn additive_homomorphism() {
        let rng = &mut thread_rng();
        let n = 52;

        let commit_key = Pedersen::setup(rng, n);

        let r1 = Scalar::rand(rng);
        let r2 = Scalar::rand(rng);

        let v1: Vec<Scalar> = sample_vector(rng, n);
        let v2: Vec<Scalar> = sample_vector(rng, n);

        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);

        let v3 = v1
            .iter()
            .zip(v2.iter())
            .map(|(&a, &b)| a * alpha + b * beta)
            .collect::<Vec<_>>();
        let r3 = alpha * r1 + beta * r2;

        let commit_v1 = Pedersen::commit(&commit_key, &v1, r1).unwrap();
        let commit_v2 = Pedersen::commit(&commit_key, &v2, r2).unwrap();
        let commit_v3 = Pedersen::commit(&commit_key, &v3, r3).unwrap();

        let expected = commit_v1.mul(alpha) + commit_v2.mul(beta);

        assert_eq!(expected, commit_v3)
    }

    #[test]
    fn short_commitment() {
        let rng = &mut thread_rng();
        let n = 10;

        let commit_key = Pedersen::setup(rng, n);

        let r = Scalar::rand(rng);

        let s1 = Scalar::rand(rng);
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

        let r = Scalar::rand(rng);

        let s1 = Scalar::rand(rng);

        let too_long = vec![s1; n + 2];

        let _commit = Pedersen::commit(&commit_key, &too_long, r).unwrap();
    }
}
