use super::BarnettSmartProtocol;
use super::{Mask, Remask, Reveal};

use crate::error::CardProtocolError;

use anyhow::Result;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, One, PrimeField, ToBytes};
use ark_marlin::rng::FiatShamirRng;
use ark_std::rand::Rng;
use ark_std::Zero;
use blake2::Blake2s;
use proof_essentials::error::CryptoError;
use proof_essentials::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::vector_commitment::pedersen::PedersenCommitment;
use proof_essentials::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
use proof_essentials::zkp::{
    arguments::shuffle,
    proofs::{chaum_pedersen_dl_equality, schnorr_identification},
    ArgumentOfKnowledge,
};
use std::marker::PhantomData;

// mod key_ownership;
mod masking;
mod remasking;
mod reveal;
mod tests;

pub struct DLCards<'a, C: ProjectiveCurve> {
    _group: &'a PhantomData<C>,
}

pub struct Parameters<C: ProjectiveCurve> {
    m: usize,
    n: usize,
    enc_parameters: el_gamal::Parameters<C>,
    commit_parameters: pedersen::CommitKey<C>,
    generator: el_gamal::Generator<C>,
}

impl<C: ProjectiveCurve> Parameters<C> {
    pub fn new(
        m: usize,
        n: usize,
        enc_parameters: el_gamal::Parameters<C>,
        commit_parameters: pedersen::CommitKey<C>,
        generator: el_gamal::Generator<C>,
    ) -> Self {
        Self {
            m,
            n,
            enc_parameters,
            commit_parameters,
            generator,
        }
    }
}

pub type PublicKey<C> = el_gamal::PublicKey<C>;

pub type PlayerSecretKey<C> = el_gamal::SecretKey<C>;

/// An open playing card. In this Discrete Log-based implementation of the Barnett-Smart card protocol
/// a card is an el-Gamal plaintext. We create a type alias to implement the `Mask` trait on it.
pub type Card<C> = el_gamal::Plaintext<C>;

/// A masked (flipped) playing card. Note that a player masking a card will know the mapping from
/// open to masked card. All other players must remask to guarantee that the card is privately masked.
/// We create a type alias to implement the `Mask` trait on it.
pub type MaskedCard<C> = el_gamal::Ciphertext<C>;

/// A `RevealToken` is computed by players when they wish to reveal a given card. These tokens can
/// then be aggregated to reveal the card.
pub type RevealToken<C> = el_gamal::Plaintext<C>;

const KEY_OWN_RNG_SEED: &'static [u8] = b"Key Ownership Proof";
const MASKING_RNG_SEED: &'static [u8] = b"Masking Proof";
const REMASKING_RNG_SEED: &'static [u8] = b"Remasking Proof";
const REVEAL_RNG_SEED: &'static [u8] = b"Reveal Proof";
const SHUFFLE_RNG_SEED: &'static [u8] = b"Shuffle Proof";

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

    type ZKProofKeyOwnership = schnorr_identification::proof::Proof<C>;
    type ZKProofMasking = chaum_pedersen_dl_equality::proof::Proof<C>;
    type ZKProofRemasking = chaum_pedersen_dl_equality::proof::Proof<C>;
    type ZKProofReveal = chaum_pedersen_dl_equality::proof::Proof<C>;
    type ZKProofShuffle = shuffle::proof::Proof<Self::Scalar, Self::Enc, Self::Comm>;

    fn setup<R: Rng>(
        rng: &mut R,
        m: usize,
        n: usize,
    ) -> Result<Self::Parameters, CardProtocolError> {
        let enc_parameters = Self::Enc::setup(rng)?;
        let commit_parameters = Self::Comm::setup(rng, n);
        let generator = Self::Enc::generator(rng)?;

        Ok(Self::Parameters::new(
            m,
            n,
            enc_parameters,
            commit_parameters,
            generator,
        ))
    }

    fn player_keygen<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
    ) -> Result<(Self::PlayerPublicKey, Self::PlayerSecretKey), CardProtocolError> {
        let (pk, sk) = Self::Enc::keygen(&pp.enc_parameters, rng)?;

        Ok((pk, sk))
    }

    fn prove_key_ownership<B: ToBytes, R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        sk: &Self::PlayerSecretKey,
        player_public_info: &B,
    ) -> Result<Self::ZKProofKeyOwnership, CryptoError> {
        let mut fs_rng =
            FiatShamirRng::<Blake2s>::from_seed(&to_bytes![KEY_OWN_RNG_SEED, player_public_info]?);

        schnorr_identification::SchnorrIdentification::prove(
            rng,
            &pp.enc_parameters.generator,
            pk,
            sk,
            &mut fs_rng,
        )
    }

    fn verify_key_ownership<B: ToBytes>(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        player_public_info: &B,
        proof: &Self::ZKProofKeyOwnership,
    ) -> Result<(), CryptoError> {
        let mut fs_rng =
            FiatShamirRng::<Blake2s>::from_seed(&to_bytes![KEY_OWN_RNG_SEED, player_public_info]?);
        schnorr_identification::SchnorrIdentification::verify(
            &pp.enc_parameters.generator,
            pk,
            proof,
            &mut fs_rng,
        )
    }

    fn compute_aggregate_key<B: ToBytes>(
        pp: &Self::Parameters,
        player_keys_proof_info: &Vec<(Self::PlayerPublicKey, Self::ZKProofKeyOwnership, B)>,
    ) -> Result<Self::AggregatePublicKey, CardProtocolError> {
        let zero = Self::PlayerPublicKey::zero();

        let mut acc = zero;
        for (pk, proof, player_public_info) in player_keys_proof_info {
            Self::verify_key_ownership(pp, pk, player_public_info, proof)?;
            acc = acc + *pk;
        }

        Ok(acc)
    }

    fn mask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_card: &Self::Card,
        r: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ZKProofMasking), CardProtocolError> {
        let masked_card = original_card.mask(&pp.enc_parameters, shared_key, r)?;
        let gen = pp.enc_parameters.generator;

        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(&gen, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -Self::Scalar::one();
        let negative_original = original_card.0.mul(minus_one).into_affine();
        let statement_cipher = masked_card.1 + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&masked_card.0, &statement_cipher);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![MASKING_RNG_SEED]?);
        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            r,
            &mut fs_rng,
        )?;

        Ok((masked_card, proof))
    }

    fn verify_mask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        card: &Self::Card,
        masked_card: &Self::MaskedCard,
        proof: &Self::ZKProofMasking,
    ) -> Result<(), CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&pp.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -Self::Scalar::one();
        let negative_original = card.0.mul(minus_one).into_affine();
        let statement_cipher = masked_card.1 + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&masked_card.0, &statement_cipher);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![MASKING_RNG_SEED]?);
        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            proof,
            &mut fs_rng,
        )
    }

    fn remask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_card: &Self::MaskedCard,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ZKProofRemasking), CardProtocolError> {
        let remasked = original_card.remask(&pp.enc_parameters, shared_key, alpha)?;

        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&pp.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -C::ScalarField::one();
        let negative_original = *original_card * minus_one;
        let statement_cipher = remasked + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![REMASKING_RNG_SEED]?);
        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            alpha,
            &mut fs_rng,
        )?;

        Ok((remasked, proof))
    }

    fn verify_remask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_masked: &Self::MaskedCard,
        remasked: &Self::MaskedCard,
        proof: &Self::ZKProofRemasking,
    ) -> Result<(), CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&pp.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -C::ScalarField::one();
        let negative_original = *original_masked * minus_one;
        let statement_cipher = *remasked + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![REMASKING_RNG_SEED]?);
        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            proof,
            &mut fs_rng,
        )
    }

    fn compute_reveal_token<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        sk: &Self::PlayerSecretKey,
        pk: &Self::PlayerPublicKey,
        masked_card: &Self::MaskedCard,
    ) -> Result<(Self::RevealToken, Self::ZKProofReveal), CardProtocolError> {
        let reveal_token: RevealToken<C> =
            el_gamal::Plaintext(masked_card.0.into().mul(sk.into_repr()).into_affine());

        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(
            &masked_card.0,
            &pp.enc_parameters.generator,
        );

        // Map to Chaum-Pedersen parameters
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&reveal_token.0, pk);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![REVEAL_RNG_SEED]?);
        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            sk,
            &mut fs_rng,
        )?;

        Ok((reveal_token, proof))
    }

    fn verify_reveal(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        reveal_token: &Self::RevealToken,
        masked_card: &Self::MaskedCard,
        proof: &Self::ZKProofReveal,
    ) -> Result<(), CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(
            &masked_card.0,
            &pp.enc_parameters.generator,
        );

        // Map to Chaum-Pedersen parameters
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&reveal_token.0, pk);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![REVEAL_RNG_SEED]?);
        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            proof,
            &mut fs_rng,
        )
    }

    fn unmask(
        pp: &Self::Parameters,
        decryption_key: &Vec<(
            Self::RevealToken,
            Self::ZKProofReveal,
            Self::PlayerPublicKey,
        )>,
        masked_card: &Self::MaskedCard,
    ) -> Result<Self::Card, CardProtocolError> {
        let zero = Self::RevealToken::zero();

        let mut aggregate_token = zero;

        for (token, proof, pk) in decryption_key {
            Self::verify_reveal(pp, pk, token, masked_card, proof)?;

            aggregate_token = aggregate_token + *token;
        }

        let decrypted = aggregate_token.reveal(masked_card)?;

        Ok(decrypted)
    }

    fn shuffle_and_remask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        deck: &Vec<Self::MaskedCard>,
        masking_factors: &Vec<Self::Scalar>,
        permutation: &Permutation,
    ) -> Result<(Vec<Self::MaskedCard>, Self::ZKProofShuffle), CardProtocolError> {
        let permuted_deck = permutation.permute_array(&deck);
        let masked_shuffled = permuted_deck
            .iter()
            .zip(masking_factors.iter())
            .map(|(masked_card, masking_factor)| {
                masked_card.remask(&pp.enc_parameters, &shared_key, masking_factor)
            })
            .collect::<Result<Vec<_>, CardProtocolError>>()?;

        let shuffle_parameters = shuffle::Parameters::new(
            &pp.enc_parameters,
            shared_key,
            &pp.commit_parameters,
            &pp.generator,
        );

        let shuffle_statement = shuffle::Statement::new(deck, &masked_shuffled, pp.m, pp.n);

        let witness = shuffle::Witness::new(permutation, masking_factors);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![SHUFFLE_RNG_SEED]?);
        let proof = shuffle::ShuffleArgument::prove(
            rng,
            &shuffle_parameters,
            &shuffle_statement,
            &witness,
            &mut fs_rng,
        )?;

        Ok((masked_shuffled, proof))
    }

    fn verify_shuffle(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_deck: &Vec<Self::MaskedCard>,
        shuffled_deck: &Vec<Self::MaskedCard>,
        proof: &Self::ZKProofShuffle,
    ) -> Result<(), CryptoError> {
        let shuffle_parameters = shuffle::Parameters::new(
            &pp.enc_parameters,
            shared_key,
            &pp.commit_parameters,
            &pp.generator,
        );

        let shuffle_statement = shuffle::Statement::new(original_deck, shuffled_deck, pp.m, pp.n);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![SHUFFLE_RNG_SEED]?);
        shuffle::ShuffleArgument::verify(
            &shuffle_parameters,
            &shuffle_statement,
            proof,
            &mut fs_rng,
        )
    }
}
