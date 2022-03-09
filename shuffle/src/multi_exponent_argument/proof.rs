use super::super::transcript::TranscriptProtocol;
use super::{Parameters, Statement};
use crate::error::Error;
use crate::utils::{DotProduct, DotProductCalculator, HomomorphicCommitment, PedersenCommitment};
use ark_crypto_primitives::encryption::elgamal::{Parameters as ElGamalParameters, Randomness};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use merlin::Transcript;
use std::iter;
use verifiable_threshold_masking_protocol::discrete_log_vtmp::{
    DiscreteLogVTMF, ElgamalCipher, VerifiableThresholdMaskingProtocol,
};

pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    // Round 1
    pub(crate) a_0_commit: C,
    pub(crate) commit_b_k: Vec<C>,
    pub(crate) vector_e_k: Vec<ElgamalCipher<C>>,

    // Round 2
    pub(crate) r_blinded: C::ScalarField,
    pub(crate) b_blinded: C::ScalarField,
    pub(crate) s_blinded: C::ScalarField,
    pub(crate) tau_blinded: C::ScalarField,
    pub(crate) a_blinded: Vec<C::ScalarField>,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify(
        &self,
        proof_parameters: &Parameters<C>,
        encryption_parameters: &ElGamalParameters<C>,
        statement: &Statement<C>,
    ) -> Result<(), Error> {
        let m = statement.shuffled_ciphers.len();
        let n = statement.shuffled_ciphers[0].len();
        let num_of_diagonals = 2 * m - 1;

        let mut transcript = Transcript::new(b"multi_exponent_argument");

        transcript.append(b"public_key", proof_parameters.public_key);
        transcript.append(b"commit_key", proof_parameters.commit_key);

        transcript.append(
            b"commitments_to_exponents",
            statement.commitments_to_exponents,
        );
        transcript.append(b"product", &statement.product);
        transcript.append(b"shuffled_ciphers", statement.shuffled_ciphers);

        transcript.append(b"m", &m);
        transcript.append(b"n", &n);
        transcript.append(b"num_of_diagonals", &num_of_diagonals);

        transcript.append(b"a_0_commit", &self.a_0_commit);
        transcript.append(b"commit_B_k", &self.commit_b_k);
        transcript.append(b"vector_E_k", &self.vector_e_k);

        let challenge: C::ScalarField = transcript.challenge_scalar(b"x");

        // Precompute all powers of the challenge from 0 to number_of_diagonals
        let challenge_powers = iter::once(C::ScalarField::one())
            .chain(iter::once(challenge))
            .chain(
                (1..num_of_diagonals).scan(challenge, |current_power, _exp| {
                    *current_power *= challenge;
                    Some(*current_power)
                }),
            )
            .collect::<Vec<_>>();

        // take vector x: x, x^2, x^3, ..., x^m
        let x_array = challenge_powers[1..m + 1].to_vec();

        // assert_eq!(
        //     self.commit_b_k[m],
        //     PedersenCommitment::<C>::commit_scalar(proof_parameters.commit_key[0], *proof_parameters.commit_key.last().unwrap(), C::ScalarField::zero(), C::ScalarField::zero())
        // );

        let left = self.commit_b_k[m];
        let right = PedersenCommitment::<C>::commit_scalar(
            proof_parameters.commit_key[0],
            *proof_parameters.commit_key.last().unwrap(),
            C::ScalarField::zero(),
            C::ScalarField::zero(),
        );

        if left != right {
            return Err(Error::MultiExpVerficationError);
        }

        if self.vector_e_k[m] != statement.product {
            return Err(Error::MultiExpVerficationError);
        }

        let c_a_x = DotProductCalculator::<C>::scalars_by_points(
            &x_array,
            &statement.commitments_to_exponents,
        )
        .unwrap();
        let verifier_commit_a = PedersenCommitment::<C>::commit_vector(
            &proof_parameters.commit_key,
            &self.a_blinded,
            self.r_blinded,
        );

        if c_a_x + self.a_0_commit != verifier_commit_a {
            return Err(Error::MultiExpVerficationError);
        }

        let c_b_k =
            DotProductCalculator::<C>::scalars_by_points(&challenge_powers, &self.commit_b_k)
                .unwrap();
        let verif_commit_b = PedersenCommitment::<C>::commit_scalar(
            proof_parameters.commit_key[0],
            *proof_parameters.commit_key.last().unwrap(),
            self.b_blinded,
            self.s_blinded,
        );
        if c_b_k != verif_commit_b {
            return Err(Error::MultiExpVerficationError);
        }

        let sum_e_k =
            DotProductCalculator::<C>::scalars_by_ciphers(&challenge_powers, &self.vector_e_k)
                .unwrap();
        let aggregate_masking_cipher = DiscreteLogVTMF::<C>::mask(
            encryption_parameters,
            &proof_parameters.public_key,
            &proof_parameters
                .masking_generator
                .mul(self.b_blinded.into_repr())
                .into_affine(),
            &Randomness(self.tau_blinded),
        )
        .unwrap();

        /*
            c1 * x^m-1; x[m-1]
            c2 * x^m-2; x[m-2]
            c3 * x^m-3; x[m-3]
            ...
            cm * x^m-m; x[0]
        */

        let verif_rhs: ElgamalCipher<C> = challenge_powers
            .iter()
            .take(m)
            .rev()
            .zip(statement.shuffled_ciphers.iter())
            .map(|(power_of_x, cipher_chunk)| {
                // x^m - i * a_vec
                let xm_minus_i_times_a = self
                    .a_blinded
                    .iter()
                    .map(|element_of_a| *element_of_a * *power_of_x)
                    .collect::<Vec<C::ScalarField>>();
                DotProductCalculator::<C>::scalars_by_ciphers(&xm_minus_i_times_a, cipher_chunk)
                    .unwrap()
            })
            .sum();

        if sum_e_k != aggregate_masking_cipher + verif_rhs {
            return Err(Error::MultiExpVerficationError);
        }

        Ok(())
    }
}
