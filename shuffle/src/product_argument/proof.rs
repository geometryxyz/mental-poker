use ark_ec::ProjectiveCurve;
use ark_ff::{Zero, PrimeField};

use merlin::Transcript;
use crate::transcript::TranscriptProtocol;

use crate::utils::commit;
use crate::config::PublicConfig;
use crate::error::Error;

pub struct Proof<C, const SIZE: usize> 
where 
    C: ProjectiveCurve
{
    pub(crate) a_commit: C,
    pub(crate) d_commit: C,
    pub(crate) delta_ds_commit: C,
    pub(crate) diff_commit: C,
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
        config: &PublicConfig<C, SIZE>, 
        b: C::ScalarField,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        transcript.append(b"a_commit", &self.a_commit);

        transcript.append(b"d_commit", &self.d_commit);
        transcript.append(b"delta_ds_commit", &self.delta_ds_commit);
        transcript.append(b"diff_commit", &self.diff_commit);

        let x: C::ScalarField = transcript.challenge_scalar(b"x");

        assert_eq!(self.b_blinded.len(), SIZE);
        assert_eq!(self.a_blinded.len(), SIZE);
        assert_eq!(self.b_blinded[0], self.a_blinded[0]);
        assert_eq!(self.b_blinded[SIZE - 1], x * b);

        let a_blinded_commit = commit::<C>(&config.commit_key, &self.a_blinded, self.r_blinded);
        let ca_x_cd = self.a_commit.mul(x.into_repr()) + self.d_commit;

        if ca_x_cd != a_blinded_commit {
            return Err(Error::ProductArgumentVerificationError)
        }

        let c_diff_x_c_delta = self.diff_commit.mul(x.into_repr()) + self.delta_ds_commit;

        //TODO implement this with windows&iters
        let mut consecutives = vec![C::ScalarField::zero(); SIZE - 1];
        for i in 0..SIZE-1 {
            consecutives[i] = x*self.b_blinded[i + 1] - self.b_blinded[i]*self.a_blinded[i + 1];
        }

        let consecutive_commit = commit::<C>(&config.commit_key, &consecutives, self.s_blinded);

        if c_diff_x_c_delta != consecutive_commit {
            return Err(Error::ProductArgumentVerificationError)
        }

        Ok(())
    }
}