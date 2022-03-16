use super::BarnettSmartProtocol;
use super::{Mask, Provable, Remask, Reveal, Verifiable};

use crate::error::CardProtocolError;

use anyhow::Result;
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::Zero;
use crypto_primitives::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};
// use crypto_primitives::utils::permutation::Permutation;
use crypto_primitives::error::CryptoError;
use crypto_primitives::vector_commitment::pedersen::PedersenCommitment;
use crypto_primitives::zkp::{
    proofs::chaum_pedersen_dl_equality, proofs::schnorr_identification, ArgumentOfKnowledge,
};
use std::marker::PhantomData;

mod masking;
mod remasking;
mod reveal;
mod tests;

pub struct DLCards<'a, C: ProjectiveCurve> {
    _group: &'a PhantomData<C>,
}

#[derive(Copy, Clone)]
pub struct Parameters<C: ProjectiveCurve> {
    enc_parameters: el_gamal::Parameters<C>,
    // commit_parameters: pedersen::CommitKey<C>,
    // key_own_parameter: C::Affine,
    // chaum_pedersen_parameters: chaum_pedersen_dl_equality::Parameters<C>
}

type PublicKey<C> = el_gamal::PublicKey<C>;

type PlayerSecretKey<C> = el_gamal::SecretKey<C>;

/// An open playing card. In this Discrete Log-based implementation of the Barnett-Smart card protocol
/// a card is an el-Gamal plaintext. We create a type alias to implement the `Mask` trait on it.
type Card<C> = el_gamal::Plaintext<C>;

/// A masked (flipped) playing card. Note that a player masking a card will know the mapping from
/// open to masked card. All other players must remask to guarantee that the card is privately masked.
/// We create a type alias to implement the `Mask` trait on it.
type MaskedCard<C> = el_gamal::Ciphertext<C>;

/// A `RevealToken` is computed by players when they wish to reveal a given card. These tokens can
/// then be aggregated to reveal the card.
type RevealToken<C> = el_gamal::Plaintext<C>;

impl<'a, C: ProjectiveCurve> BarnettSmartProtocol for DLCards<'a, C> {
    type Scalar = C::ScalarField;
    type Enc = ElGamal<C>;
    type Comm = PedersenCommitment<C>;
    type Parameters = Parameters<C>;
    type PlayerPublicKey = PublicKey<C>;
    type PlayerSecretKey = PlayerSecretKey<C>;
    type AggregatePublicKey = PublicKey<C>;

    type Card = Card<C>;
    type MaskedCard = MaskedCard<C>;
    type RevealToken = RevealToken<C>;

    type KeyOwnArg = schnorr_identification::SchnorrIdentification<C>;
    type MaskingArg = chaum_pedersen_dl_equality::DLEquality<C>;
    type RemaskingArg = chaum_pedersen_dl_equality::DLEquality<C>;
    type RevealArg = chaum_pedersen_dl_equality::DLEquality<C>;

    type ProofKeyOwnership = schnorr_identification::proof::Proof<C>;
    type ProofMasking = masking::Proof<C>;
    type ProofRemasking = remasking::Proof<C>;
    type ProofReveal = reveal::Proof<C>;

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
        rng: &mut R,
        pp: &Self::Parameters,
    ) -> Result<(Self::PlayerPublicKey, Self::PlayerSecretKey), CardProtocolError> {
        let (pk, sk) = Self::Enc::keygen(&pp.enc_parameters, rng)?;

        Ok((pk, sk))
    }

    fn prove_key_ownership<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        sk: &Self::PlayerSecretKey,
    ) -> Result<Self::ProofKeyOwnership, CryptoError> {
        Self::KeyOwnArg::prove(rng, &pp.enc_parameters.generator, pk, sk)
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

    fn mask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        message: &Self::Card,
        r: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ProofMasking), CardProtocolError> {
        let masked = message.mask(&pp.enc_parameters, shared_key, r)?;
        let statement = masking::Statement::new(*message, masked, (*pp, *shared_key));

        let proof = statement.prove(rng, *r)?;

        Ok((masked, proof))
    }

    fn remask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original: &Self::MaskedCard,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ProofRemasking), CardProtocolError> {
        let remasked = original.remask(&pp.enc_parameters, shared_key, alpha)?;
        let statement = remasking::Statement::new(*original, remasked, (*pp, *shared_key));
        let proof = statement.prove(rng, *alpha)?;

        Ok((remasked, proof))
    }

    fn compute_reveal_token<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        sk: &Self::PlayerSecretKey,
        pk: &Self::PlayerPublicKey,
        ciphertext: &Self::MaskedCard,
    ) -> Result<(Self::RevealToken, Self::ProofReveal), CardProtocolError> {
        let reveal_token: RevealToken<C> =
            el_gamal::Plaintext(ciphertext.0.into().mul(sk.into_repr()).into_affine());
        let statement = reveal::Statement::new(*ciphertext, reveal_token, (*pp, *pk));
        let proof = statement.prove(rng, *sk)?;

        Ok((reveal_token, proof))
    }

    fn unmask(
        pp: &Self::Parameters,
        decryption_key: &Vec<(Self::RevealToken, Self::ProofReveal, Self::PlayerPublicKey)>,
        cipher: &Self::MaskedCard,
    ) -> Result<Self::Card, CardProtocolError> {
        let zero = Self::RevealToken::zero();

        let mut aggregate_token = zero;

        for (token, proof, pk) in decryption_key {
            let statement = reveal::Statement::new(*cipher, *token, (*pp, *pk));
            proof.verify(&statement)?;
            aggregate_token = aggregate_token + *token;
        }

        let decrypted = aggregate_token.reveal(cipher)?;

        Ok(decrypted)
    }
}
