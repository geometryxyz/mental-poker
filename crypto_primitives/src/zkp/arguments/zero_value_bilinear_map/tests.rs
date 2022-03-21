#[cfg(test)]
mod test {
    use crate::error::CryptoError;
    use crate::utils::rand::sample_vector;
    use crate::utils::vector_arithmetic::reshape;
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use crate::zkp::{arguments::zero_value_bilinear_map, ArgumentOfKnowledge};

    use super::super::YMapping;
    use ark_ff::Zero;
    use ark_std::{rand::thread_rng, UniformRand};
    use starknet_curve;
    use std::iter::Iterator;

    // Choose ellitptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Type aliases for concrete instances using the chosen EC.
    type Comm = pedersen::PedersenCommitment<Curve>;
    type Witness<'a> = zero_value_bilinear_map::Witness<'a, Scalar>;
    type Statement<'a> = zero_value_bilinear_map::Statement<'a, Scalar, Comm>;
    type ZeroValueArgument<'a> = zero_value_bilinear_map::ZeroValueArgument<'a, Scalar, Comm>;
    type Parameters<'a> = zero_value_bilinear_map::Parameters<'a, Scalar, Comm>;

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

        let commit_key = Comm::setup(rng, n);

        let random_scalars: Vec<Scalar> = sample_vector(rng, m * n);
        let a_chunks = reshape(&random_scalars, m, n).unwrap();

        let r: Vec<Scalar> = sample_vector(rng, a_chunks.len());
        let a_commits = a_chunks
            .iter()
            .zip(r.iter())
            .map(|(a_chunk, &random)| Comm::commit(&commit_key, a_chunk, random).unwrap())
            .collect::<Vec<_>>();

        let zeros = vec![Scalar::zero(); m * n];
        let b_chunks = zeros.chunks(n).map(|c| c.to_vec()).collect::<Vec<_>>();

        let s: Vec<Scalar> = sample_vector(rng, a_chunks.len());
        let b_commits = b_chunks
            .iter()
            .zip(s.iter())
            .map(|(b_chunk, &random)| Comm::commit(&commit_key, b_chunk, random).unwrap())
            .collect::<Vec<_>>();

        let proof_parameters = Parameters::new(m, n, &commit_key);

        let y = Scalar::rand(rng);
        let test_mapping = YMapping::new(y, n);

        let statement = Statement::new(&a_commits, &b_commits, &test_mapping);

        let valid_witness = Witness::new(&a_chunks, &r, &b_chunks, &s);

        let valid_proof =
            ZeroValueArgument::prove(rng, &proof_parameters, &statement, &valid_witness).unwrap();

        assert_eq!(Ok(()), valid_proof.verify(&proof_parameters, &statement));

        let bad_witness = Witness::new(&a_chunks, &r, &a_chunks, &r);

        let invalid_proof =
            ZeroValueArgument::prove(rng, &proof_parameters, &statement, &bad_witness).unwrap();

        assert_eq!(
            Err(CryptoError::ProofVerificationError(String::from(
                "Zero Argument (5.2)",
            ))),
            ZeroValueArgument::verify(&proof_parameters, &statement, &invalid_proof)
        );
    }
}
