use ark_ec::{ProjectiveCurve};
use rand::{thread_rng, seq::SliceRandom};
use ark_std::{UniformRand};
use merlin::Transcript;
use ark_ff::Field;

use crate::{
    config::PublicConfig,
    transcript::TranscriptProtocol,
    utils::{HomomorphicCommitment, PedersenCommitment},
    product_argument::{proof::Proof as ProductArgumentProof, prover::Prover as ProductArgumentProver},
    proof::Proof
};

pub struct Prover<C, const SIZE: usize>
where 
    C: ProjectiveCurve
{
    public_config: PublicConfig<C, SIZE>,
    transcript: Transcript,
    permutation: Vec<u64>,
}

impl<C, const SIZE: usize> Prover<C, SIZE>
where 
    C: ProjectiveCurve
{
    pub fn new(public_config: PublicConfig<C, SIZE>, label: &'static [u8]) -> Self {
        Self {
            public_config,
            transcript: Transcript::new(label),
            permutation: Self::generate_permutation()
        }
    }

    pub fn create_proof(&self) -> Proof<C, SIZE> {
        let mut transcript = self.transcript.clone();

        transcript.append(b"commit_key", &self.public_config.commit_key);

        let mut rng = ark_std::rand::thread_rng();

        let r = C::ScalarField::rand(&mut rng);
        let permutation_in_field = self.permutation.iter().map(|p_i| C::ScalarField::from(*p_i)).collect::<Vec<_>>();
        let pi_commit = PedersenCommitment::<C>::commit_vector(&self.public_config.commit_key, &permutation_in_field, r);

        transcript.append(b"pi_commit", &pi_commit);
        let x: C::ScalarField = transcript.challenge_scalar(b"x");

        let r_x = C::ScalarField::rand(&mut rng);
        let exp_pi = self.permutation.iter().map(|p_i| {
            x.pow(Self::as_limbs(*p_i))
        }).collect::<Vec<_>>();

        let exp_pi_commit = PedersenCommitment::<C>::commit_vector(&self.public_config.commit_key, &exp_pi, r_x);
        transcript.append(b"exp_pi_commit", &exp_pi_commit);

        let y: C::ScalarField = transcript.challenge_scalar(b"y");
        let z: C::ScalarField = transcript.challenge_scalar(b"z");

        let mut identity_permutation: Vec<u64> = Vec::with_capacity(SIZE);
        for i in 0..SIZE {
            identity_permutation.push(i as u64);
        }

        let b: C::ScalarField = identity_permutation.iter()
                .map(|i| C::ScalarField::from(*i)*y + x.pow(Self::as_limbs(*i)) - z)
                .collect::<Vec<_>>()
                .iter()
                .product();

        //All shared data should always be added in transcript
        transcript.append(b"b", &b);

        let a = permutation_in_field.iter().zip(exp_pi.iter()).map(|(pi, x_pi)| {
            *pi*y + x_pi - z
        }).collect::<Vec<_>>();

        let a_rand = y*r + r_x;
        let a_commit = PedersenCommitment::<C>::commit_vector(&self.public_config.commit_key, &a, a_rand);

        let prod_arg_proof: ProductArgumentProof<C, SIZE> = ProductArgumentProver::create_proof(&self.public_config.commit_key, &mut transcript, a, a_commit, a_rand);
        Proof {
            pi_commit,
            exp_pi_commit,
            product_argument_proof: prod_arg_proof
        }
    }

    fn generate_permutation() -> Vec<u64> {
        let mut rng = thread_rng();
        let mut permutation: Vec<u64> = Vec::with_capacity(SIZE);
        for i in 0..SIZE {
            permutation.push(i as u64);
        }
        permutation.shuffle(&mut rng);
        permutation
    }

    fn as_limbs(p_i: u64) -> [u64; 4] {
        [p_i, 0, 0, 0]
    }
}

#[cfg(test)]
mod test {
    use crate::{
        config::PublicConfig,
    };
    use rand::thread_rng;
    use merlin::Transcript;

    use starknet_curve::Projective;
    use super::Prover;

    #[test]
    fn initial_proof_creation() {
        let mut rng = thread_rng();

        let config = PublicConfig::<Projective, 1000>::new(&mut rng);

        let prover = Prover::<Projective, 1000>::new(config.clone(), b"shuffle");
        let proof = prover.create_proof();

        let mut transcript = Transcript::new(b"shuffle");
        assert_eq!(proof.verify(&config, &mut transcript), Ok(()));
    }
}