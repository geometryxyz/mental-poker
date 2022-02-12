use ark_crypto_primitives::{
    commitment::{
        pedersen::Randomness,
    },
};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::Zero;

use merlin::Transcript;
use crate::product_argument::transcript::TranscriptProtocol;

use crate::utils::commit;
use crate::config::PublicConfig;

pub struct Proof<C, const SIZE: usize> 
where 
    C: ProjectiveCurve
{
    pub(crate) d_commit: C::Affine,
    pub(crate) a_commit: C::Affine,
    pub(crate) delta_ds_commit: C::Affine,
    pub(crate) diff_commit: C::Affine,
    pub(crate) a_blinded: Vec<C::ScalarField>,
    pub(crate) b_blinded: Vec<C::ScalarField>,
    pub(crate) r_blinded: C::ScalarField,
    pub(crate) s_blinded: C::ScalarField,
}

impl<C, const SIZE: usize> Proof<C, SIZE> 
    where
        C: ProjectiveCurve
{
    pub fn verify(&self, 
        config: PublicConfig<C>, 
        b: C::ScalarField,
        transcript: &mut Transcript,
    ) -> bool {
        transcript.append(b"a_commit", &self.a_commit);
        transcript.append(b"b", &b);

        transcript.append(b"d_commit", &self.d_commit);
        transcript.append(b"delta_ds_commit", &self.delta_ds_commit);
        transcript.append(b"diff_commit", &self.diff_commit);

        let x: C::ScalarField = transcript.challenge_scalar(b"x");

        assert_eq!(self.b_blinded.len(), SIZE);
        assert_eq!(self.a_blinded.len(), SIZE);
        assert_eq!(self.b_blinded[0], self.a_blinded[0]);
        assert_eq!(self.b_blinded[SIZE - 1], x * b);

        let a_blinded_commit = commit(&config.parameters, &self.a_blinded, &Randomness(self.r_blinded));
        let ca_x_cd = self.a_commit.mul(x).into_affine() + self.d_commit;
        assert_eq!(ca_x_cd, a_blinded_commit);

        let c_diff_x_c_delta = self.diff_commit.mul(x).into_affine() + self.delta_ds_commit;

        let mut consecutives = vec![C::ScalarField::zero(); SIZE - 1];
        for i in 0..SIZE-1 {
            consecutives[i] = x*self.b_blinded[i + 1] - self.b_blinded[i]*self.a_blinded[i + 1];
        }

        let consecutive_commit = commit(&config.parameters, &consecutives, &Randomness(self.s_blinded));
        assert_eq!(c_diff_x_c_delta, consecutive_commit);

        true
    }
}

#[cfg(test)]
mod test {
    use crate::{
        product_argument::prover::Prover,
    };
    use starknet_curve::{Projective};
    use ark_std::{test_rng, UniformRand};
    use crate::config::{PublicConfig};
    use starknet_curve::{Fr};
    use merlin::Transcript;

    #[test]
    fn test_proof() {
        let public_randomnes = &mut test_rng();
        let config = PublicConfig::<Projective>::new(public_randomnes);

        let rng = &mut test_rng();
        let a1 = Fr::rand(rng);
        let a2 = Fr::rand(rng);
        let a3 = Fr::rand(rng);

        let a = vec![a1, a2, a3];
        let b = a1 * a2 * a3;
        let prover = Prover::<Projective, 3>::new(config.clone(), b"product_argument", a.as_slice().try_into().unwrap(), b);
        let proof = prover.create_proof();

        let mut transcript = Transcript::new(b"product_argument");
        assert_eq!(proof.verify(config, b, &mut transcript), true);
    }
}