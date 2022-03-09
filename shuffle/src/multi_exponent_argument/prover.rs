use super::proof::Proof;
use super::{Parameters, Statement, Witness};
use crate::error::Error;
use crate::{
    transcript::TranscriptProtocol,
    utils::{
        DotProduct, DotProductCalculator, HomomorphicCommitment, PedersenCommitment, RandomSampler,
        ScalarSampler,
    },
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use std::iter;
use std::marker::PhantomData;
use verifiable_threshold_masking_protocol::discrete_log_vtmp::{
    DiscreteLogVTMF, ElgamalCipher, VerifiableThresholdMaskingProtocol,
};

use ark_crypto_primitives::encryption::{
    elgamal::{Parameters as ElGamalParameters, Randomness},
    AsymmetricEncryptionScheme,
};
use ark_ff::{One, Zero};
use merlin::Transcript;
use rand::Rng;

pub struct Prover<'a, C, EncryptionScheme: AsymmetricEncryptionScheme>
where
    C: ProjectiveCurve,
{
    parameters: &'a Parameters<'a, C>,
    transcript: Transcript,
    statement: &'a Statement<'a, C>,
    witness: &'a Witness<'a, C>,
    _scheme: PhantomData<EncryptionScheme>,
}

impl<'a, C: ProjectiveCurve, EncryptionScheme: AsymmetricEncryptionScheme>
    Prover<'a, C, EncryptionScheme>
{
    pub fn new(
        parameters: &'a Parameters<'a, C>,
        statement: &'a Statement<'a, C>,
        witness: &'a Witness<'a, C>,
    ) -> Self {
        //TODO add dimension assertions
        Self {
            parameters,
            transcript: Transcript::new(b"multi_exponent_argument"),
            statement,
            witness,
            _scheme: PhantomData::<EncryptionScheme>,
        }
    }

    pub fn prove<R: Rng>(
        &self,
        rng: &mut R,
        encryption_parameters: &ElGamalParameters<C>,
    ) -> Proof<C> {
        let mut transcript = self.transcript.clone();

        transcript.append(b"public_key", self.parameters.public_key);
        transcript.append(b"commit_key", self.parameters.commit_key);

        transcript.append(
            b"commitments_to_exponents",
            self.statement.commitments_to_exponents,
        );
        transcript.append(b"product", &self.statement.product);
        transcript.append(b"shuffled_ciphers", self.statement.shuffled_ciphers);

        let m = self.witness.matrix_a.len();
        let n = self.witness.matrix_a[0].len();
        let num_of_diagonals = 2 * m - 1;

        transcript.append(b"m", &m);
        transcript.append(b"n", &n);
        transcript.append(b"num_of_diagonals", &num_of_diagonals);

        let a_0 = ScalarSampler::<C>::sample_vector(rng, n);
        let r_0 = ScalarSampler::<C>::sample_element(rng);

        let mut b = ScalarSampler::<C>::sample_vector(rng, num_of_diagonals + 1);
        let mut s = ScalarSampler::<C>::sample_vector(rng, num_of_diagonals + 1);
        let mut tau = ScalarSampler::<C>::sample_vector(rng, num_of_diagonals + 1);

        b[m] = C::ScalarField::zero();
        s[m] = C::ScalarField::zero();
        tau[m] = self.witness.rho;

        let a_0_commit =
            PedersenCommitment::<C>::commit_vector(&self.parameters.commit_key.to_vec(), &a_0, r_0);

        let commit_b_k = b
            .iter()
            .zip(s.iter())
            .map(|(b_k, s_k)| {
                PedersenCommitment::<C>::commit_scalar(
                    self.parameters.commit_key[0],
                    *self.parameters.commit_key.last().unwrap(),
                    *b_k,
                    *s_k,
                )
            })
            .collect::<Vec<_>>();

        let diagonals = Self::diagonals_from_chunks(
            &self.statement.shuffled_ciphers,
            &self.witness.matrix_a,
            &a_0,
        )
        .unwrap();

        let vector_e_k = b
            .iter()
            .zip(tau.iter())
            .zip(diagonals.iter())
            .map(|((b_k, tau_k), d_k)| {
                let encrypted_random = DiscreteLogVTMF::<C>::mask(
                    encryption_parameters,
                    self.parameters.public_key,
                    &self.parameters.masking_generator.mul(*b_k).into_affine(),
                    &Randomness::<C>(*tau_k),
                );
                encrypted_random.unwrap() + *d_k
            })
            .collect::<Vec<ElgamalCipher<C>>>();

        transcript.append(b"a_0_commit", &a_0_commit);
        transcript.append(b"commit_B_k", &commit_b_k);
        transcript.append(b"vector_E_k", &vector_e_k);

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

        let scalar_products_ax = self
            .witness
            .matrix_a
            .iter()
            .enumerate()
            .map(|(i, chunk)| {
                chunk
                    .iter()
                    .map(|scalar| x_array[i] * scalar)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<Vec<C::ScalarField>>>();

        let mut a_blinded: Vec<C::ScalarField> = Vec::with_capacity(n);

        // c0[0]x + c1[0]x^2 ... cm[0]x^m = b[0]
        // c0[1]x + c1[1]x^2 ... cm[1]x^m = b[1]
        // c0[2]x + c1[2]x^2 ... cm[2]x^m
        // c0[3]x + c1[3]x^2 ... cm[3]x^m
        // ...
        // c0[n]x + c1[n]x^2 ... cm[n]x^m = b[n]
        for i in 0..n {
            let mut poly = a_0[i];
            for j in 0..m {
                poly = poly + scalar_products_ax[j][i];
            }
            a_blinded.push(poly);
        }

        let r_blinded = r_0
            + DotProductCalculator::<C>::scalars_by_scalars(
                &self.witness.matrix_blinders,
                &x_array,
            )
            .unwrap();
        let b_blinded =
            DotProductCalculator::<C>::scalars_by_scalars(&b, &challenge_powers).unwrap();
        let s_blinded =
            DotProductCalculator::<C>::scalars_by_scalars(&s, &challenge_powers).unwrap();
        let tau_blinded =
            DotProductCalculator::<C>::scalars_by_scalars(&tau, &challenge_powers).unwrap();

        Proof {
            // Round 1
            a_0_commit,
            commit_b_k,
            vector_e_k,

            // Round 2
            r_blinded,
            b_blinded,
            s_blinded,
            tau_blinded,
            a_blinded,
        }
    }

    fn diagonals_from_chunks(
        cipher_chunks: &Vec<Vec<ElgamalCipher<C>>>,
        scalar_chunks: &Vec<Vec<C::ScalarField>>,
        a_0_randomness: &Vec<C::ScalarField>,
    ) -> Result<Vec<ElgamalCipher<C>>, Error> {
        let m = cipher_chunks.len();
        let num_of_diagonals = 2 * m - 1;

        let mut diagonal_sums: Vec<ElgamalCipher<C>> =
            vec![ElgamalCipher::zero(); num_of_diagonals];
        let center = num_of_diagonals / 2 as usize;

        for d in 1..m {
            let additional_randomness = DotProductCalculator::<C>::scalars_by_ciphers(
                &a_0_randomness,
                &cipher_chunks[d - 1],
            )
            .unwrap();
            let mut tmp_product1 = ElgamalCipher::zero();
            let mut tmp_product2 = ElgamalCipher::zero();
            for i in d..m {
                let dot = DotProductCalculator::<C>::scalars_by_ciphers(
                    &scalar_chunks[i - d],
                    &cipher_chunks[i],
                )
                .unwrap();
                tmp_product1 = tmp_product1 + dot;

                let dot = DotProductCalculator::<C>::scalars_by_ciphers(
                    &scalar_chunks[i],
                    &cipher_chunks[i - d],
                )
                .unwrap();
                tmp_product2 = tmp_product2 + dot;
            }

            diagonal_sums[center - d] = tmp_product1 + additional_randomness;
            diagonal_sums[center + d] = tmp_product2;
        }

        let product: ElgamalCipher<C> = cipher_chunks
            .iter()
            .zip(scalar_chunks.iter())
            .map(|(c_i, a_i)| DotProductCalculator::<C>::scalars_by_ciphers(a_i, c_i).unwrap())
            .sum();

        diagonal_sums[center] = product;

        let zeroth_diagonal = DotProductCalculator::<C>::scalars_by_ciphers(
            &a_0_randomness,
            &cipher_chunks.last().unwrap(),
        )
        .unwrap();
        diagonal_sums.insert(0, zeroth_diagonal);

        Ok(diagonal_sums)
    }
}

#[cfg(test)]
mod test {

    use super::{DotProduct, DotProductCalculator};
    use ark_crypto_primitives::encryption::elgamal::{ElGamal, Randomness};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::Zero;
    use ark_std::{
        rand::{seq::SliceRandom, thread_rng},
        UniformRand,
    };
    use starknet_curve::{Fr, Projective};

    use crate::utils::{
        HomomorphicCommitment, PedersenCommitment, PointSampler, RandomSampler, ScalarSampler,
    };

    use super::*;
    use std::iter::Iterator;

    fn generate_permutation(length: usize) -> Vec<usize> {
        let mut rng = thread_rng();
        let mut permutation: Vec<usize> = Vec::with_capacity(length);
        for i in 0..length {
            permutation.push(i);
        }
        permutation.shuffle(&mut rng);
        permutation
    }

    fn generate_commit_key<R: Rng, C: ProjectiveCurve>(
        public_randomess: &mut R,
        len: &usize,
    ) -> Vec<C::Affine> {
        let mut commit_key = Vec::with_capacity(len + 1);
        let mut base = C::rand(public_randomess);
        for _ in 0..len + 1 {
            commit_key.push(base.into_affine());
            base.double_in_place();
        }
        commit_key
    }

    #[test]
    fn proof_verification_test() {
        let number_of_cards = 52;
        let m = 4;
        let n = 13;
        let rng = &mut thread_rng();

        let number_of_ciphers = m * n;

        let elgamal_parameters = DiscreteLogVTMF::setup(rng).unwrap();
        let (master_pk, _) =
            DiscreteLogVTMF::<Projective>::keygen(&elgamal_parameters, rng).unwrap();

        let card_attributes = PointSampler::<Projective>::sample_vector(rng, number_of_ciphers);
        let masking_factors = ScalarSampler::<Projective>::sample_vector(rng, number_of_cards);
        let deck_of_cards = card_attributes
            .iter()
            .zip(masking_factors.iter())
            .map(|(attribute, masking_factor)| {
                DiscreteLogVTMF::<Projective>::mask(
                    &elgamal_parameters,
                    &master_pk,
                    &attribute.into_affine(),
                    &Randomness(*masking_factor),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let permutation = generate_permutation(number_of_cards);

        let shuffle_maskings = ScalarSampler::<Projective>::sample_vector(rng, number_of_cards);
        let a_chunks = shuffle_maskings
            .chunks(n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();
        let shuffle_maskings_to_rand = shuffle_maskings
            .iter()
            .map(|x| Randomness(*x))
            .collect::<Vec<_>>();

        let shuffled_deck = DiscreteLogVTMF::<Projective>::mask_shuffle(
            &elgamal_parameters,
            &master_pk,
            &deck_of_cards,
            &shuffle_maskings_to_rand,
            &permutation,
        )
        .unwrap();
        let c_chunks = shuffled_deck
            .chunks(n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let commit_key = generate_commit_key::<_, Projective>(rng, &n);

        let product_raw = DotProductCalculator::<Projective>::scalars_by_ciphers(
            &shuffle_maskings,
            &shuffled_deck,
        )
        .unwrap();
        let rho = Fr::rand(rng);
        let product = DiscreteLogVTMF::<Projective>::remask(
            &elgamal_parameters,
            &master_pk,
            &product_raw,
            &Randomness(rho),
        )
        .unwrap();
        let masking_generator = Projective::rand(rng).into_affine();

        let mask = DiscreteLogVTMF::<Projective>::mask(
            &elgamal_parameters,
            &master_pk,
            &masking_generator.mul(Fr::zero()).into_affine(),
            &Randomness::<Projective>(rho),
        )
        .unwrap();
        assert_eq!(product, product_raw + mask);

        let r = ScalarSampler::<Projective>::sample_vector(rng, a_chunks.len());
        let c_a = a_chunks
            .iter()
            .zip(r.iter())
            .map(|(a_chunk, random)| {
                PedersenCommitment::commit_vector(&commit_key, a_chunk, *random)
            })
            .collect::<Vec<_>>();

        let proof_parameters =
            Parameters::<Projective>::new(&master_pk, &commit_key, masking_generator);
        let witness = Witness::new(&a_chunks, &r, rho);
        let statement = Statement::new(&c_chunks, product, &c_a);

        let prover: Prover<Projective, ElGamal<Projective>> =
            Prover::<Projective, ElGamal<Projective>>::new(&proof_parameters, &statement, &witness);

        let proof = prover.prove(rng, &elgamal_parameters);

        assert_eq!(
            Ok(()),
            proof.verify(&proof_parameters, &elgamal_parameters, &statement)
        );
    }
}
