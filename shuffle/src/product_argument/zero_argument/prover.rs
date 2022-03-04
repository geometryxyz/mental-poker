use super::{Statement, Parameters, Witness, BilinearMap, proof::Proof};

use crate::{
    error::Error,
    utils::{
        ScalarSampler, RandomSampler, PedersenCommitment, HomomorphicCommitment, DotProduct, DotProductCalculator}, 
    transcript::TranscriptProtocol
};

use ark_ec::{ProjectiveCurve};
use ark_ff::{Zero, One};
use merlin::Transcript;
use rand::Rng;
use std::iter;


pub struct Prover<'a, C>
where 
    C: ProjectiveCurve,
{
    parameters: &'a Parameters<'a, C>,
    transcript: Transcript,
    statement: &'a Statement<'a, C>,
    witness: &'a Witness<'a, C>, 
}

impl<'a, C: ProjectiveCurve> Prover<'a, C> {
    pub fn new(
        parameters: &'a Parameters<'a, C>,
        statement: &'a Statement<'a, C>,
        witness: &'a Witness<'a, C>
    ) -> Self {

        Self {
            parameters, 
            transcript: Transcript::new(b"zero_argument"),
            statement, 
            witness
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R) -> Proof<C> {
        let mut transcript = self.transcript.clone();

        let a_0 = ScalarSampler::<C>::sample_vector(rng, self.parameters.n);
        let b_m = ScalarSampler::<C>::sample_vector(rng, self.parameters.n);

        let r_0 = ScalarSampler::<C>::sample_element(rng);
        let s_m = ScalarSampler::<C>::sample_element(rng);

        let a_0_commit = PedersenCommitment::<C>::commit_vector(self.parameters.commit_key, &a_0, r_0);
        let b_m_commit = PedersenCommitment::<C>::commit_vector(self.parameters.commit_key, &b_m, s_m);

        let a_0_vec = vec![a_0.clone(); 1];
        let extended_a = [&a_0_vec[..], &self.witness.matrix_a[..]].concat();

        let b_m_vec = vec![b_m.clone(); 1];
        let extended_b = [&self.witness.matrix_b[..], &b_m_vec[..]].concat();

        let diagonals = self.diagonals_from_chunks(&extended_a, &extended_b, self.parameters.m+1, C::ScalarField::zero()).unwrap();

        let mut t = ScalarSampler::<C>::sample_vector(rng, 2*self.parameters.m + 1);
        t[self.parameters.m + 1] = C::ScalarField::zero();

        let vector_of_commited_diagonals = diagonals.iter().zip(t.iter()).map(|(&diagonal, &random)|{
            PedersenCommitment::<C>::commit_scalar(self.parameters.commit_key[0], *self.parameters.commit_key.last().unwrap(), diagonal, random)
        }).collect::<Vec<_>>();

        // Public parameters
        transcript.append(b"commit_key", self.parameters.commit_key);
        transcript.append(b"m", &self.parameters.m);
        transcript.append(b"n", &self.parameters.n);

        // Random values
        transcript.append(b"c_a_0", &a_0_commit);
        transcript.append(b"c_b_m", &b_m_commit);

        // Commitments
        transcript.append(b"commitment_to_a", self.statement.commitment_to_a);
        transcript.append(b"commitment_to_b", self.statement.commitment_to_b);
        transcript.append(b"vector_of_commited_diagonals", &vector_of_commited_diagonals);

        let x: C::ScalarField = transcript.challenge_scalar(b"x");

        // Precompute all powers of the challenge from 0 to number_of_diagonals
        let challenge_powers =
        iter::once(C::ScalarField::one())
        .chain(iter::once(x))
        .chain(
            (1..2*self.parameters.m).scan(x, |current_power, _exp| {
                *current_power *= x;
                Some(*current_power)
            })
        )
        .collect::<Vec<_>>();

        let first_m_powers = challenge_powers[0..self.parameters.m].to_vec();
        let mut first_m_powers_reversed = first_m_powers[..].to_vec();
        first_m_powers_reversed.reverse();
        
        let first_m_non_zero_powers = challenge_powers[1..self.parameters.m+1].to_vec();
        let mut first_m_non_zero_powers_reversed = first_m_non_zero_powers[..].to_vec();
        first_m_non_zero_powers_reversed.reverse();

        // a1[0]x + a2[0]x^2 ... am[0]x^m
        // a1[1]x + a2[1]x^2 ... am[1]x^m
        // a1[2]x + a2[2]x^2 ... am[2]x^m
        // a1[3]x + a2[3]x^2 ... am[3]x^m
        // ...
        // a1[n]x + a2[n]x^2 ... am[n]x^m = b[n]
        let mut a_blinded: Vec<C::ScalarField> = Vec::with_capacity(self.parameters.m + 1);
        for i in 0..self.parameters.n {
            let mut poly = a_0[i];
            for j in 0..self.parameters.m {
                poly = poly + self.witness.matrix_a[j][i] * first_m_non_zero_powers[j];
            }
            a_blinded.push(poly);
        }

        let mut b_blinded: Vec<C::ScalarField> = Vec::with_capacity(self.parameters.m + 1);
        for i in 0..self.parameters.n {
            let mut poly = b_m[i];
            for j in 0..self.parameters.m {
                poly = poly + self.witness.matrix_b[j][i] * first_m_non_zero_powers_reversed[j];
            }
            b_blinded.push(poly);
        }

        let r_blinded = r_0 + DotProductCalculator::<C>::scalars_by_scalars(&self.witness.randoms_for_a_commit, &first_m_non_zero_powers).unwrap();
        let s_blinded = DotProductCalculator::<C>::scalars_by_scalars(&self.witness.randoms_for_b_commit, &first_m_non_zero_powers_reversed).unwrap() + s_m;
        let t_blinded = DotProductCalculator::<C>::scalars_by_scalars(&t, &challenge_powers).unwrap();


        Proof {
            a_0_commit, 
            b_m_commit,
            vector_of_commited_diagonals,

            a_blinded, 
            b_blinded, 
            r_blinded,
            s_blinded,
            t_blinded
        }    
    }

    fn diagonals_from_chunks(
        &self,
        a_chunks: &Vec<Vec<C::ScalarField>>,
        b_chunks: &Vec<Vec<C::ScalarField>>,
        statement_diagonal: usize,
        statement_value: C::ScalarField,
    )
     -> Result<Vec<C::ScalarField>, Error> {

        if a_chunks.len() != b_chunks.len() {
            return Err(Error::DiagonalLengthError);
        }
    
        let m = a_chunks.len();
        let num_of_diagonals = 2 * m - 1;
    
        let mut diagonal_sums: Vec<C::ScalarField> = vec![C::ScalarField::zero(); num_of_diagonals];
        let center = num_of_diagonals/2 as usize;
    
        for d in 1..m {
            let mut tmp_product1 = C::ScalarField::zero(); 
            let mut tmp_product2 = C::ScalarField::zero(); 
            for i in d..m {
                let dot = self.statement.bilinear_map.compute_mapping(&a_chunks[i - d], &b_chunks[i]).unwrap();
                tmp_product1 = tmp_product1 + dot;
    
                let dot = self.statement.bilinear_map.compute_mapping(&a_chunks[i], &b_chunks[i - d]).unwrap();
                tmp_product2 = tmp_product2 + dot;
            }
    
            diagonal_sums[center - d] = tmp_product1;
            diagonal_sums[center + d] = tmp_product2;
        }

        let product: C::ScalarField = a_chunks.iter().zip(b_chunks.iter()).map(|(a_i, b_i)| {
            self.statement.bilinear_map.compute_mapping(a_i, b_i).unwrap()
        }).sum();

        diagonal_sums[center] = product;
        diagonal_sums[statement_diagonal] = statement_value;
    
        Ok(diagonal_sums)  
    }

}
