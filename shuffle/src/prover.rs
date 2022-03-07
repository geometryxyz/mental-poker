use ark_ec::{ProjectiveCurve};
use super::{Statement, Parameters, Witness};
use crate::{
    transcript::TranscriptProtocol,
    utils::{RandomSampler, ScalarSampler, HomomorphicCommitment, PedersenCommitment, DotProduct, DotProductCalculator}
};
use verifiable_threshold_masking_protocol::discrete_log_vtmp::{VerifiableThresholdMaskingProtocol, DiscreteLogVTMF};
use std::iter;
use std::marker::PhantomData;

use merlin::Transcript;
use rand::Rng;
use ark_crypto_primitives::{encryption::{AsymmetricEncryptionScheme, elgamal::{Randomness, Parameters as ElGamalParameters}}};
use crate::product_argument;
use crate::multi_exponent_argument;
use crate::proof::Proof;



pub struct Prover<'a, C, EncryptionScheme: AsymmetricEncryptionScheme>
where 
    C: ProjectiveCurve
{
    parameters: &'a Parameters<'a, C>,
    transcript: Transcript,
    statement: &'a Statement<'a, C>,
    witness: &'a Witness<'a, C>, 
    _scheme: PhantomData<EncryptionScheme>
}

impl<'a, C: ProjectiveCurve, EncryptionScheme: AsymmetricEncryptionScheme> Prover<'a, C, EncryptionScheme> {
    pub fn new(parameters: &'a Parameters<'a, C>, statement: &'a Statement<'a, C>, witness: &'a Witness<'a, C>) -> Self {
        //TODO add dimension assertions
        Self {
            parameters, 
            transcript: Transcript::new(b"shuffle_argument"),
            statement, 
            witness, 
            _scheme: PhantomData::<EncryptionScheme>
        }
    }

    pub fn prove<R: Rng>(&self, rng: &mut R, encryption_parameters: &ElGamalParameters<C>) -> Proof<C> {
        let mut transcript = self.transcript.clone();

        let r = ScalarSampler::<C>::sample_vector(rng, self.statement.m);

        let index = (1..=self.statement.m * self.statement.n)
            .map(|x| C::ScalarField::from(x as u64))
            .collect::<Vec<_>>();

        let a = self.witness.permutation.permute_array(&index);

        let a_chunks = a.chunks(self.statement.n).map(|c| c.to_vec()).collect::<Vec<_>>();

        let a_commits = a_chunks.iter().zip(r.iter()).map(|(a, &r)| {
            PedersenCommitment::<C>::commit_vector(self.parameters.commit_key, a, r)
        }).collect::<Vec<C>>();

        // Public data
        transcript.append(b"public_key", self.parameters.public_key);
        transcript.append(b"commit_key", self.parameters.commit_key);

        // statement
        transcript.append(b"ciphers", self.statement.input_ciphers);
        transcript.append(b"shuffled", self.statement.shuffled_ciphers);
        transcript.append(b"m", &self.statement.m);
        transcript.append(b"n", &self.statement.n);

        // round 1
        transcript.append(b"a_commits", &a_commits);

        let x: C::ScalarField = transcript.challenge_scalar(b"x");
        
        let challenge_powers =
            iter::once(x)
            .chain(
                (1..self.witness.permutation.size).scan(x, |current_power, _exp| {
                    *current_power *= x;
                    Some(*current_power)
                })
            )
        .collect::<Vec<_>>();
        
        let b = self.witness.permutation.permute_array(&challenge_powers);
        let s = ScalarSampler::<C>::sample_vector(rng, self.statement.m);
        
        let b_chunks = b.chunks(self.statement.n).map(|c| c.to_vec()).collect::<Vec<_>>();

        let b_commits = b_chunks.iter().zip(s.iter()).map(|(b, &s)| {
            PedersenCommitment::<C>::commit_vector(self.parameters.commit_key, b, s)
        }).collect::<Vec<C>>();

        //round 2
        transcript.append(b"b_commits", &b_commits);

        let y: C::ScalarField = transcript.challenge_scalar(b"y");
        let z: C::ScalarField = transcript.challenge_scalar(b"z");

        let d = a.iter().zip(b.iter()).map(|(&a, &b)| y*a + b).collect::<Vec<_>>();
        let t = r.iter().zip(s.iter()).map(|(&r, &s)| y*r + s).collect::<Vec<_>>();
        
        // Engage in product argument ---------------------------------------------------------------------
        let product_argument_parameters = product_argument::Parameters::<C>::new(
            self.statement.m,
            self.statement.n,
            &self.parameters.commit_key
        );

        let d_minus_z = d.iter().map(|&x| x - z ).collect::<Vec<C::ScalarField>>();
        let d_minus_z_chunks = d_minus_z.chunks(self.statement.n).map(|c| c.to_vec()).collect::<Vec<_>>();

        let d_minus_z_commits = d_minus_z_chunks.iter()
            .zip(t.iter())
            .map(|(chunk, &random)| {
                PedersenCommitment::<C>::commit_vector(self.parameters.commit_key, chunk, random)
            })
            .collect::<Vec<_>>();

        let claimed_product = d_minus_z.iter().product();

        let product_argument_statement = product_argument::Statement::new(
            &d_minus_z_commits,
            claimed_product
        );

        let product_argument_witness = product_argument::Witness::new(
            &d_minus_z_chunks,
            &t
        );

        let product_argument_prover = product_argument::prover::Prover::new(
            &product_argument_parameters,
            &product_argument_statement, 
            &product_argument_witness
        );

        let product_argument_proof = product_argument_prover.prove(rng);

        // Engage in multi-exponentation argument ----------------------------------------------------------
        let multi_exp_parameters = multi_exponent_argument::Parameters::<C>::new(
            &self.parameters.public_key,
            &self.parameters.commit_key,
            encryption_parameters.generator
        );

        let minus_rho_witness = self.witness.rho.iter().map(|&x| -x).collect::<Vec<_>>();
        let rho = DotProductCalculator::<C>::scalars_by_scalars(&minus_rho_witness, &b).unwrap();
  
        let temp = DotProductCalculator::<C>::scalars_by_ciphers(&b, self.statement.shuffled_ciphers).unwrap();
        let product = DiscreteLogVTMF::<C>::remask(
            encryption_parameters,
            self.parameters.public_key,
            &temp,
            &Randomness(rho),
        ).unwrap();

        let shuffled_chunks = self.statement.shuffled_ciphers.chunks(self.statement.n).map(|c| c.to_vec()).collect::<Vec<_>>();

        let multi_exp_statement = multi_exponent_argument::Statement::<C>::new(
            &shuffled_chunks,
            product,
            &b_commits
         );

        let multi_exp_witness = multi_exponent_argument::Witness::<C>::new(
            &b_chunks,
            &s,
            rho
        );

        let multi_exp_prover = multi_exponent_argument::prover::Prover::<C, EncryptionScheme>::new(
            &multi_exp_parameters,
            &multi_exp_statement,
            &multi_exp_witness
        );

        let multi_exp_proof = multi_exp_prover.prove(rng, encryption_parameters);

        // Produce proof
        Proof{
            a_commits,
            b_commits,
            product_argument_proof,
            multi_exp_proof
        }

    }
}