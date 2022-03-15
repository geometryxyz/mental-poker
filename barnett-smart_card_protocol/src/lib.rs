use crate::error::CardProtocolError;
use ark_ff::Field;
use ark_std::rand::Rng;
use crypto_primitives::homomorphic_encryption::HomomorphicEncryptionScheme;
// use crypto_primitives::utils::permutation::Permutation;
use crypto_primitives::error::CryptoError;
use crypto_primitives::vector_commitment::HomomorphicCommitmentScheme;
use crypto_primitives::zkp::ArgumentOfKnowledge;
use std::ops::{Add, Mul};

pub mod discrete_log_cards;
pub mod error;

pub trait Mask<Scalar: Field, Enc: HomomorphicEncryptionScheme<Scalar>> {
    fn mask(
        &self,
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        r: &Scalar,
    ) -> Result<Enc::Ciphertext, CardProtocolError>;
}

pub trait Remask<Scalar: Field, Enc: HomomorphicEncryptionScheme<Scalar>> {
    fn remask(
        &self,
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        r: &Scalar,
    ) -> Result<Enc::Ciphertext, CardProtocolError>;
}

pub trait Reveal<F: Field, Enc: HomomorphicEncryptionScheme<F>> {
    fn reveal(&self, cipher: &Enc::Ciphertext) -> Result<Enc::Plaintext, CardProtocolError>;
}

/// `Verifiable` designates a type that is a proof of some argument or proof system.
/// The trait allows us to benefit from Rust's type inference: as long as the method's arguments
/// are provided correctly, we will not need to specify which proof system we are using
/// when calling `some_proof.verify(&params, &statement)`.
pub trait Verifiable<A: ArgumentOfKnowledge> {
    fn verify_proof(
        &self,
        parameters: &A::CommonReferenceString,
        statement: &A::Statement,
    ) -> Result<(), CryptoError>;
}

pub trait BarnettSmartProtocol {
    // IN PROGRESS: require traits for these types as necessary

    // Cryptography
    type Scalar: Field;
    type Parameters;
    type PlayerPublicKey;
    type PlayerSecretKey;
    type AggregatePublicKey;
    type Enc: HomomorphicEncryptionScheme<Self::Scalar>;
    type Comm: HomomorphicCommitmentScheme<Self::Scalar>;

    // Cards
    type Card: Copy + Clone + Mask<Self::Scalar, Self::Enc>;
    type MaskedCard: Remask<Self::Scalar, Self::Enc>;
    type RevealToken: Add
        + Reveal<Self::Scalar, Self::Enc>
        + Mul<Self::Scalar, Output = Self::RevealToken>;

    // Argument Systems
    type KeyOwnArg: ArgumentOfKnowledge;
    type MaskingArg: ArgumentOfKnowledge;
    type RemaskingArg: ArgumentOfKnowledge;
    // type RevealArg: ArgumentOfKnowledge;
    // type ShuffleArg: ArgumentOfKnowledge;

    // Proofs
    type ProofKeyOwnership: Verifiable<Self::KeyOwnArg>;
    type ProofMasking: Verifiable<Self::MaskingArg>;
    type ProofRemasking: Verifiable<Self::RemaskingArg>;
    // type ProofReveal: Verifiable<Self::RevealArg>;
    // type ProofShuffle: Verifiable<Self::ShuffleArg>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, CardProtocolError>;

    fn player_keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PlayerPublicKey, Self::PlayerSecretKey), CardProtocolError>;

    fn prove_key_ownership(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        sk: &Self::PlayerSecretKey,
    ) -> Result<Self::ProofKeyOwnership, CryptoError>;

    fn compute_aggregate_key(
        pp: &Self::Parameters,
        player_keys: &Vec<(Self::PlayerPublicKey, Self::ProofKeyOwnership)>,
    ) -> Result<Self::AggregatePublicKey, CardProtocolError>;

    fn mask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        message: &Self::Card,
        r: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ProofMasking), CardProtocolError>;

    fn remask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        ciphertext: &Self::MaskedCard,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ProofMasking), CardProtocolError>;

    // fn compute_reveal_token(
    //     sk: &Self::PlayerSecretKey,
    //     ciphertext: &Self::MaskedCard,
    // ) -> Result<(Self::RevealToken, Self::ProofReveal), CardProtocolError>;

    // fn unmask(
    //     decryption_key: &Vec<(Self::RevealToken, Self::ProofReveal)>,
    //     cipher: &Self::MaskedCard,
    // ) -> Result<Self::Card, CardProtocolError>;

    // fn shuffle_and_remask(
    //     pp: &Self::Parameters,
    //     shared_key: &Self::AggregatePublicKey,
    //     deck: &Vec<Self::MaskedCard>,
    //     masking_factors: &Vec<Self::Scalar>,
    //     permutation: &Permutation,
    // ) -> Result<(Vec<Self::MaskedCard>, Self::ProofShuffle), CardProtocolError>;
}
