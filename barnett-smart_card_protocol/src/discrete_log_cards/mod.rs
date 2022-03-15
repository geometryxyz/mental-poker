use super::BarnettSmartProtocol;
use super::{Mask, Remask, Reveal};

use crate::error::CardProtocolError;

use anyhow::Result;
use ark_ec::ProjectiveCurve;
use ark_ff::One;
use ark_std::rand::Rng;
use ark_std::Zero;
use crypto_primitives::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};
// use crypto_primitives::utils::permutation::Permutation;
use crypto_primitives::error::CryptoError;
use crypto_primitives::vector_commitment::pedersen::PedersenCommitment;
use crypto_primitives::zkp::proofs::chaum_pedersen_dl_equality;
use crypto_primitives::zkp::proofs::schnorr_identification;
use crypto_primitives::zkp::ArgumentOfKnowledge;
use std::{marker::PhantomData, ops::Mul};

mod key_ownership;
mod masking_arg;
mod remasking_arg;
mod tests;

pub struct DLCards<'a, C: ProjectiveCurve> {
    _group: &'a PhantomData<C>,
}

pub struct Parameters<C: ProjectiveCurve> {
    enc_parameters: el_gamal::Parameters<C>,
    // commit_parameters: pedersen::CommitKey<C>,
    // key_own_parameter: C::Affine,
    // chaum_pedersen_parameters: chaum_pedersen_dl_equality::Parameters<C>
}

type PublicKey<C> = el_gamal::PublicKey<C>;

type PlayerSecretKey<C> = el_gamal::SecretKey<C>;

type Card<C> = el_gamal::Plaintext<C>;

impl<C: ProjectiveCurve> Mask<C::ScalarField, ElGamal<C>> for Card<C> {
    fn mask(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        r: &C::ScalarField,
    ) -> Result<el_gamal::Ciphertext<C>, CardProtocolError> {
        let ciphertext = ElGamal::<C>::encrypt(pp, shared_key, self, r)?;
        Ok(ciphertext)
    }
}

type MaskedCard<C> = el_gamal::Ciphertext<C>;

impl<C: ProjectiveCurve> Remask<C::ScalarField, ElGamal<C>> for MaskedCard<C> {
    fn remask(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        alpha: &C::ScalarField,
    ) -> Result<el_gamal::Ciphertext<C>, CardProtocolError> {
        let zero = el_gamal::Plaintext::zero();
        let masking_point = zero.mask(pp, shared_key, alpha)?;
        let remasked_cipher = *self + masking_point;

        Ok(remasked_cipher)
    }
}

type RevealToken<C> = el_gamal::Plaintext<C>;

impl<C: ProjectiveCurve> Reveal<C::ScalarField, ElGamal<C>> for RevealToken<C> {
    fn reveal(
        &self,
        cipher: &el_gamal::Ciphertext<C>,
    ) -> Result<el_gamal::Plaintext<C>, CardProtocolError> {
        let neg_one = -C::ScalarField::one();
        let negative_token = self.mul(neg_one);
        let decrypted = negative_token + el_gamal::Plaintext(cipher.1);

        Ok(decrypted)
    }
}

type ProofKeyOwnership<C> = schnorr_identification::proof::Proof<C>;

type ProofMasking<C> = chaum_pedersen_dl_equality::proof::Proof<C>;

type ProofRemasking<C> = chaum_pedersen_dl_equality::proof::Proof<C>;

// type ProofReveal<C> = chaum_pedersen_dl_equality::proof::Proof<C>;

impl<'a, C: ProjectiveCurve> BarnettSmartProtocol for DLCards<'a, C> {
    type Scalar = C::ScalarField;
    type Parameters = Parameters<C>;
    type PlayerPublicKey = PublicKey<C>;
    type PlayerSecretKey = PlayerSecretKey<C>;
    type AggregatePublicKey = PublicKey<C>;
    type Enc = ElGamal<C>;
    type Comm = PedersenCommitment<C>;

    type Card = Card<C>;
    type MaskedCard = MaskedCard<C>;
    type RevealToken = RevealToken<C>;

    type KeyOwnArg = key_ownership::KeyOwnershipArg<C>;
    type MaskingArg = masking_arg::MaskingArgument<C>;
    type RemaskingArg = remasking_arg::RemaskingArgument<C>;
    // type RevealArg = DLEquality<'a, C>;

    type ProofKeyOwnership = ProofKeyOwnership<C>;
    type ProofMasking = ProofMasking<C>;
    type ProofRemasking = ProofRemasking<C>;
    // type ProofReveal = ProofReveal<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, CardProtocolError> {
        let enc_parameters = Self::Enc::setup(rng)?;
        // commit_parameters: pedersen::CommitKey<C>,
        // let key_own_parameter = enc_parameters.generator;
        // chaum_pedersen_parameters: chaum_pedersen_dl_equality::Parameters<C>

        Ok(Self::Parameters {
            enc_parameters,
            // key_own_parameter,
        })
    }

    fn player_keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PlayerPublicKey, Self::PlayerSecretKey), CardProtocolError> {
        let (pk, sk) = Self::Enc::keygen(&pp.enc_parameters, rng)?;

        Ok((pk, sk))
    }

    fn prove_key_ownership(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        sk: &Self::PlayerSecretKey,
    ) -> Result<Self::ProofKeyOwnership, CryptoError> {
        Self::KeyOwnArg::prove(&pp.enc_parameters.generator, pk, sk)
    }

    fn compute_aggregate_key(
        pp: &Self::Parameters,
        player_keys: &Vec<(Self::PlayerPublicKey, Self::ProofKeyOwnership)>,
    ) -> Result<Self::AggregatePublicKey, CardProtocolError> {
        let zero = Self::PlayerPublicKey::zero();
        let crs = &pp.enc_parameters.generator;

        let mut acc = zero;

        for (pk, proof) in player_keys {
            proof.verify(&crs, pk)?;
            acc = acc + *pk;
        }

        Ok(acc)
    }

    fn mask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        message: &Self::Card,
        r: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ProofMasking), CardProtocolError> {
        let masked = message.mask(&pp.enc_parameters, shared_key, r)?;

        let crs = masking_arg::CommonReferenceString::new(pp.enc_parameters.generator, *shared_key);

        let proof = Self::MaskingArg::prove(&crs, &masking_arg::Statement(*message, masked), &r)?;

        Ok((masked, proof))
    }

    fn remask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original: &Self::MaskedCard,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ProofMasking), CardProtocolError> {
        let remasked = original.remask(&pp.enc_parameters, shared_key, alpha)?;
        let crs = remasking_arg::CommonReferenceString::new(pp.enc_parameters.generator, *shared_key);
        let proof = Self::RemaskingArg::prove(&crs, &remasking_arg::Statement::new(*original, remasked), alpha)?;

        Ok((remasked, proof))
    }
}
