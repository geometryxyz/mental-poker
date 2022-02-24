use super::{Statement, Parameters, BilinearMap};

use crate::error::Error;
use crate::utils::{PedersenCommitment, HomomorphicCommitment, DotProduct, DotProductCalculator};
use crate::transcript::TranscriptProtocol;

use ark_ec::{ProjectiveCurve};
use ark_ff::{Zero, One};
use merlin::Transcript;
use std::iter;


pub struct Proof<C> 
where 
    C: ProjectiveCurve
{
    // Round 1
    pub a_0_commit: C,
    pub b_m_commit: C,
    pub vector_of_commited_diagonals: Vec<C>,

    // Round 2
    pub a_blinded: Vec<C::ScalarField>,
    pub b_blinded: Vec<C::ScalarField>,
    pub r_blinded: C::ScalarField,
    pub s_blinded: C::ScalarField,
    pub t_blinded: C::ScalarField
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify(&self, proof_parameters: &Parameters<C>, statement: &Statement<C>) -> Result<(), Error> {

        if self.vector_of_commited_diagonals[proof_parameters.m+1] != 
            PedersenCommitment::<C>::commit_scalar(proof_parameters.commit_key[0], *proof_parameters.commit_key.last().unwrap(), C::ScalarField::zero(), C::ScalarField::zero())
            {
                return Err(Error::ZeroArgumentVerificationError);
            }

        let mut transcript = Transcript::new(b"zero_argument");

        // Public parameters
        transcript.append(b"commit_key", proof_parameters.commit_key);
        transcript.append(b"m", &proof_parameters.m);
        transcript.append(b"n", &proof_parameters.n);

        // Random values
        transcript.append(b"c_a_0", &self.a_0_commit);
        transcript.append(b"c_b_m", &self.b_m_commit);

        // Commitments
        transcript.append(b"commitment_to_a", statement.commitment_to_a);
        transcript.append(b"commitment_to_b", statement.commitment_to_b);
        transcript.append(b"vector_of_commited_diagonals", &self.vector_of_commited_diagonals);

        let x: C::ScalarField = transcript.challenge_scalar(b"x");

        // Precompute all powers of the challenge from 0 to number_of_diagonals
        let challenge_powers =
        iter::once(C::ScalarField::one())
        .chain(iter::once(x))
        .chain(
            (1..2 * proof_parameters.m).scan(x, |current_power, _exp| {
                *current_power *= x;
                Some(*current_power)
            })
        )
        .collect::<Vec<_>>();

        let first_m_powers = challenge_powers[0..proof_parameters.m].to_vec();
        let mut first_m_powers_reversed = first_m_powers[..].to_vec();
        first_m_powers_reversed.reverse();
        
        let first_m_non_zero_powers = challenge_powers[1..proof_parameters.m+1].to_vec();
        let mut first_m_non_zero_powers_reversed = first_m_powers[..].to_vec();
        first_m_non_zero_powers_reversed.reverse();

        // Verify commitment to A against a commitment on blinded a with blinded random r
        let left: C = self.a_0_commit + DotProductCalculator::<C>::scalars_by_points(&first_m_non_zero_powers, statement.commitment_to_a).unwrap();
        let right = PedersenCommitment::<C>::commit_vector(&proof_parameters.commit_key, &self.a_blinded, self.r_blinded);
        if left != right {
            return Err(Error::ZeroArgumentVerificationError);
        }
        
        // Verify commitment to B against a commitment on blinded b with blinded random s
        let left: C = self.b_m_commit + DotProductCalculator::<C>::scalars_by_points(&first_m_non_zero_powers_reversed, statement.commitment_to_b).unwrap();
        let right = PedersenCommitment::<C>::commit_vector(&proof_parameters.commit_key, &self.b_blinded, self.s_blinded);
        if left != right {
            return Err(Error::ZeroArgumentVerificationError);
        }

        
        // Verify commitments to the diagonals against a commitment on bilinear_map(blinded a, blinded a) with blinded random t
        let left = DotProductCalculator::<C>::scalars_by_points(&challenge_powers, &self.vector_of_commited_diagonals).unwrap();
        let a_star_b = statement.bilinear_map.compute_mapping(&self.a_blinded, &self.b_blinded).unwrap();
        let right = PedersenCommitment::<C>::commit_scalar(proof_parameters.commit_key[0], *proof_parameters.commit_key.last().unwrap(), a_star_b, self.t_blinded);
        if left != right {
            return Err(Error::ZeroArgumentVerificationError);
        }

        Ok(())
    }
}