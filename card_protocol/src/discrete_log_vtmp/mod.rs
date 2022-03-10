pub mod tests;

use super::VerifiableThresholdMaskingProtocol;
use anyhow::Result;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::{One, Zero};
use crypto_primitives::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme, MulByScalar,
};
use crypto_primitives::permutation::Permutation;
use crypto_primitives::zkp::proofs::{
    chaum_pedersen_dl_equality, chaum_pedersen_dl_equality::DLEquality,
};
use crypto_primitives::zkp::proofs::{
    schnorr_identification, schnorr_identification::SchnorrIdentification,
};
use crypto_primitives::zkp::ArgumentOfKnowledge;
use std::iter::Iterator;
use std::marker::PhantomData;

pub struct DiscreteLogVTMF<'a, C: ProjectiveCurve> {
    _group: &'a PhantomData<C>,
}

impl<'a, C: ProjectiveCurve> VerifiableThresholdMaskingProtocol<ElGamal<C>>
    for DiscreteLogVTMF<'a, C>
{
    type DecryptionKey = C;
    type DLEqualityProof = chaum_pedersen_dl_equality::proof::Proof<C>;
    type PrivateKeyProof = schnorr_identification::proof::Proof<C>;

    fn setup<R: Rng>(rng: &mut R) -> anyhow::Result<el_gamal::Parameters<C>> {
        let setup = ElGamal::<C>::setup(rng)?;
        Ok(setup)
    }

    fn keygen<R: Rng>(
        pp: &el_gamal::Parameters<C>,
        rng: &mut R,
    ) -> Result<(el_gamal::PublicKey<C>, el_gamal::SecretKey<C>)> {
        let (pk, sk) = ElGamal::<C>::keygen(pp, rng)?;
        Ok((pk, sk))
    }

    fn verified_keygen<R: Rng>(
        pp: &el_gamal::Parameters<C>,
        rng: &mut R,
    ) -> Result<(
        el_gamal::PublicKey<C>,
        el_gamal::SecretKey<C>,
        Self::PrivateKeyProof,
    )> {
        let (pk, sk) = ElGamal::<C>::keygen(pp, rng)?;

        let params = schnorr_identification::Parameters::new(pp.generator);
        let pk_projective = pk.into_projective();
        let statement = schnorr_identification::Statement::<C>::new(&pk_projective);
        let witness = schnorr_identification::Witness::<C>::new(&sk);

        let proof = SchnorrIdentification::<C>::prove(&params, &statement, &witness)?;

        Ok((pk, sk, proof))
    }

    fn mask(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        message: &el_gamal::Plaintext<C>,
        r: &el_gamal::Randomness<C>,
    ) -> Result<el_gamal::Ciphertext<C>> {
        let ciphertext = ElGamal::<C>::encrypt(pp, shared_key, message, r)?;
        Ok(ciphertext)
    }

    fn verified_mask(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        message: &el_gamal::Plaintext<C>,
        r: &el_gamal::Randomness<C>,
    ) -> Result<(el_gamal::Ciphertext<C>, Self::DLEqualityProof)> {
        let ciphertext = Self::mask(&pp, &shared_key, &message, &r)?;

        let proof_parameters =
            chaum_pedersen_dl_equality::Parameters::<C>::new(pp.generator, *shared_key);
        let negative_message = message.mul(-C::ScalarField::one());
        let statement_cipher = negative_message.add_mixed(&ciphertext.1).into_affine();
        let statement =
            chaum_pedersen_dl_equality::Statement::new(&ciphertext.0, &statement_cipher);
        let witness = chaum_pedersen_dl_equality::Witness::new(r);
        let proof = DLEquality::prove(&proof_parameters, &statement, &witness)?;
        Ok((ciphertext, proof))
    }

    fn compute_decryption_key(
        sk: &el_gamal::SecretKey<C>,
        ciphertext: &el_gamal::Ciphertext<C>,
    ) -> Result<Self::DecryptionKey> {
        let decryption_key = ciphertext.0.mul(sk.into_repr());

        Ok(decryption_key)
    }

    fn unmask(
        decryption_key: &Self::DecryptionKey,
        cipher: &el_gamal::Ciphertext<C>,
    ) -> Result<el_gamal::Plaintext<C>> {
        let neg = -decryption_key.into_affine();
        let decrypted = neg + cipher.1;

        Ok(decrypted)
    }

    fn remask(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        ciphertext: &el_gamal::Ciphertext<C>,
        alpha: &el_gamal::Randomness<C>,
    ) -> Result<el_gamal::Ciphertext<C>> {
        let masking_point = Self::mask(pp, shared_key, &C::Affine::zero(), alpha)?;
        let remasked_cipher = *ciphertext + masking_point;

        Ok(remasked_cipher)
    }

    fn verified_remask(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        ciphertext: &el_gamal::Ciphertext<C>,
        alpha: &el_gamal::Randomness<C>,
    ) -> Result<(el_gamal::Ciphertext<C>, Self::DLEqualityProof)> {
        let masking_point = Self::mask(pp, shared_key, &C::Affine::zero(), alpha)?;
        let remasked_cipher = *ciphertext + masking_point;

        let proof_parameters =
            chaum_pedersen_dl_equality::Parameters::new(pp.generator, *shared_key);
        let neg_one = -C::ScalarField::one();
        let negative_cipher = ciphertext.mul(neg_one);
        let statement_cipher = remasked_cipher + negative_cipher;

        let statement =
            chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);
        let witness = chaum_pedersen_dl_equality::Witness::new(alpha);

        let proof = DLEquality::prove(&proof_parameters, &statement, &witness)?;

        Ok((remasked_cipher, proof))
    }

    fn mask_shuffle(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        deck: &Vec<el_gamal::Ciphertext<C>>,
        masking_factors: &Vec<el_gamal::Randomness<C>>,
        permutation: &Permutation,
    ) -> Result<Vec<el_gamal::Ciphertext<C>>> {
        assert_eq!(masking_factors.len(), deck.len());

        let permuted_deck = permutation.permute_array(deck);

        let mask_shuffled_deck = permuted_deck
            .iter()
            .zip(masking_factors.iter())
            .map(|(card, masking_factor)| -> Result<_> {
                let remasked = Self::remask(pp, shared_key, &card, masking_factor)?;
                Ok(remasked)
            })
            .collect::<Result<Vec<el_gamal::Ciphertext<C>>>>()?;

        Ok(mask_shuffled_deck)
    }
}
