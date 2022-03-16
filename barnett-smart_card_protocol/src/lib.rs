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

/// A general statement of a computation containing an input, an output and some public parameters.
/// Private parameters are omitted as these need to remain secret. We will later immplement the [Provable]
/// trait for specific instances of these computation statements in order to prove computational integroty
/// in zk (without revealing the private inputs).
pub struct ComputationStatement<In, Out, P> {
    input: In,
    output: Out,
    public_parameters: P,
}

impl<In, Out, P> ComputationStatement<In, Out, P> {
    pub fn new(input: In, output: Out, public_parameters: P) -> Self {
        Self {
            input,
            output,
            public_parameters,
        }
    }
}

/// Defines a statement that is provable using a given proof or argument system.
pub trait Provable<A: ArgumentOfKnowledge> {
    type Output;
    type Witness;

    fn prove(&self, witness: Self::Witness) -> Result<Self::Output, CryptoError>;
}

/// Defines a proof of a statement provable in a given proof or argument system
pub trait Verifiable<A: ArgumentOfKnowledge> {
    type Statement: Provable<A>;

    fn verify(&self, statement: &Self::Statement) -> Result<(), CryptoError>;
}

/// Mental Poker protocol based on the one described by Barnett and Smart (2003).
/// The protocol has been modified to make use of the argument of a correct shuffle presented
/// by Bayer and Groth (2014).
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
    type RevealArg: ArgumentOfKnowledge;
    // type ShuffleArg: ArgumentOfKnowledge;

    // Proofs
    type ProofKeyOwnership;
    type ProofMasking: Verifiable<Self::MaskingArg>;
    type ProofRemasking: Verifiable<Self::RemaskingArg>;
    type ProofReveal: Verifiable<Self::RevealArg>;
    // type ProofShuffle: Verifiable<Self::ShuffleArg>;

    /// Randomly produce the scheme parameters
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, CardProtocolError>;

    /// Generate keys for a player.
    fn player_keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PlayerPublicKey, Self::PlayerSecretKey), CardProtocolError>;

    /// Prove in zero knowledge that the owner of a public key `pk` knows the corresponding secret key `sk`
    fn prove_key_ownership(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        sk: &Self::PlayerSecretKey,
    ) -> Result<Self::ProofKeyOwnership, CryptoError>;

    /// Use all the public keys and zk-proofs to compute a verified aggregate public key
    fn compute_aggregate_key(
        pp: &Self::Parameters,
        player_keys: &Vec<(Self::PlayerPublicKey, Self::ProofKeyOwnership)>,
    ) -> Result<Self::AggregatePublicKey, CardProtocolError>;

    /// Use the shared public key and a (private) random scalar `alpha` to mask a card.
    /// Returns a masked card and a zk-proof that the masking operation was applied correctly.
    fn mask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        message: &Self::Card,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ProofMasking), CardProtocolError>;

    /// Use the shared public key and a (private) random scalar `alpha` to remask a masked card.
    /// Returns a masked card and a zk-proof that the remasking operation was applied correctly.
    fn remask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        ciphertext: &Self::MaskedCard,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ProofRemasking), CardProtocolError>;

    /// Players can use this function to compute their reveal token for a given masked card.
    /// The token is accompanied by a proof that it is a valid reveal for the specified card issued
    /// by the player who ran the computation.
    fn compute_reveal_token(
        pp: &Self::Parameters,
        sk: &Self::PlayerSecretKey,
        pk: &Self::PlayerPublicKey,
        ciphertext: &Self::MaskedCard,
    ) -> Result<(Self::RevealToken, Self::ProofReveal), CardProtocolError>;

    /// After collecting all the necessary reveal tokens and proofs that these are correctly issued,
    /// players can unmask a masked card to recover the underlying card.
    fn unmask(
        pp: &Self::Parameters,
        decryption_key: &Vec<(Self::RevealToken, Self::ProofReveal, Self::PlayerPublicKey)>,
        cipher: &Self::MaskedCard,
    ) -> Result<Self::Card, CardProtocolError>;

    // fn shuffle_and_remask(
    //     pp: &Self::Parameters,
    //     shared_key: &Self::AggregatePublicKey,
    //     deck: &Vec<Self::MaskedCard>,
    //     masking_factors: &Vec<Self::Scalar>,
    //     permutation: &Permutation,
    // ) -> Result<(Vec<Self::MaskedCard>, Self::ProofShuffle), CardProtocolError>;
}
