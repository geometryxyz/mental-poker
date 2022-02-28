#[cfg(test)]
mod test {
    use crate::{
        utils::{RandomSampler, ScalarSampler, HomomorphicCommitment, PedersenCommitment, HadamardProductCalculator, HadamardProduct},
        error::Error,
    };
    use ark_ec::{ProjectiveCurve};
    use ark_ff::{Zero, One};
    use starknet_curve::{Projective, Fr};
    use ark_std::rand::{thread_rng};
    use crate::product_argument::{zero_argument::YMapping, zero_argument};
    use crate::product_argument::hadamard_product_argument::{prover::Prover, Statement, Parameters, Witness};
    use std::iter::Iterator;
    use rand::Rng;


    fn generate_commit_key<R: Rng, C: ProjectiveCurve>(public_randomess: &mut R, len: &usize) -> Vec<C::Affine> {
        let mut commit_key = Vec::with_capacity(len + 1);
        let mut base = C::rand(public_randomess);
        for _ in 0..len + 1 {
            commit_key.push(base.into_affine());
            base.double_in_place();
        }
        commit_key
    }

    #[test] 
    fn test_hadamard_product_argument() {
        let m = 4;
        let n = 13;

        let rng = &mut thread_rng();

        let commit_key = generate_commit_key::<_, Projective>(rng, &n);

        let random_scalars = ScalarSampler::<Projective>::sample_vector(rng, m*n);
        let a_chunks = random_scalars.chunks(n).map(|c| c.to_vec()).collect::<Vec<_>>();

        let r = ScalarSampler::<Projective>::sample_vector(rng, a_chunks.len());
        let a_commits = a_chunks.iter().zip(r.iter()).map(|(a_chunk, &random)|{
            PedersenCommitment::commit_vector(&commit_key, a_chunk, random)
        }).collect::<Vec<Projective>>();

        let b = a_chunks.iter().fold(vec![Fr::one(); n], |x, y| {
            HadamardProductCalculator::<Projective>::scalars_by_scalars(&x, &y).unwrap()
        });

        let product = b.iter().fold(Fr::one(), |x, y| {
            x * y
        });
        
        let raw_prod = random_scalars.iter().fold(Fr::one(), |x, y| {
            x * y
        });

        assert_eq!(product, raw_prod);

        let s = ScalarSampler::<Projective>::sample_element(rng);
        let b_commit = PedersenCommitment::<Projective>::commit_vector(&commit_key, &b, s);

        let proof_parameters = Parameters::<Projective>::new(m, n, &commit_key);
        let statement = Statement::new(&a_commits, b_commit);

        let valid_witness = Witness::<Projective>::new(&a_chunks, &r, &b, s);

        let honest_prover = Prover::new(&proof_parameters, &statement, &valid_witness);

        let valid_proof = honest_prover.prove(rng);

        // assert_eq!(Ok(()), valid_proof.verify(&proof_parameters, &statement));

        // let bad_witness = Witness::<Projective>::new(&a_chunks, &r, &a_chunks, &r);

        // let malicious_prover = Prover::new(&proof_parameters, &statement, &bad_witness);

        // let invalid_proof = malicious_prover.prove(rng);

        // assert_eq!(Err(Error::ZeroArgumentVerificationError), invalid_proof.verify(&proof_parameters, &statement));
    }
}