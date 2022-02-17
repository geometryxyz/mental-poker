pub mod error;
pub mod discrete_log_vtmp;
pub mod chaum_pedersen_dl_equality;
pub mod transcript;
pub mod schnorr_identification;

use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_std::rand::Rng;
use error::Error;
use std::ops::{Add, Mul};


trait VerifiableThresholdMaskingProtocol<EncryptionScheme: AsymmetricEncryptionScheme> {
    type DecryptionKey;
    type ScalarField;
    type Ciphertext: Add<Self::Ciphertext> + Mul<Self::ScalarField>;
    type DLEqualityProof;
    type PrivateKeyProof;

    fn setup<R: Rng>(rng: &mut R) -> Result<EncryptionScheme::Parameters, Error>;
    
    fn keygen<R: Rng>(
        pp: &EncryptionScheme::Parameters,
        rng: &mut R
    ) -> Result<(EncryptionScheme::PublicKey, EncryptionScheme::SecretKey), Error>;
    
    fn verified_keygen<R: Rng>(
        pp: &EncryptionScheme::Parameters,
        rng: &mut R
    ) -> Result<(EncryptionScheme::PublicKey, EncryptionScheme::SecretKey, Self::PrivateKeyProof), Error>;

    fn mask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        message: &EncryptionScheme::Plaintext,
        r: &EncryptionScheme::Randomness
    ) -> Result<Self::Ciphertext, Error>;

    fn verified_mask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        message: &EncryptionScheme::Plaintext,
        r: &EncryptionScheme::Randomness
    ) -> Result<(Self::Ciphertext, Self::DLEqualityProof), Error>;

    fn compute_decryption_key(
        sk: &EncryptionScheme::SecretKey,
        ciphertext: &Self::Ciphertext
    ) -> Result<Self::DecryptionKey, Error>;

    fn unmask(
        decryption_key: &Self::DecryptionKey,
        cipher: &Self::Ciphertext,
    ) -> Result<EncryptionScheme::Plaintext, Error>;

    fn remask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        ciphertext: &Self::Ciphertext,
        alpha: &EncryptionScheme::Randomness
    ) -> Result<Self::Ciphertext, Error>;

    fn verified_remask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        ciphertext: &Self::Ciphertext,
        alpha: &EncryptionScheme::Randomness
    ) -> Result<(Self::Ciphertext, Self::DLEqualityProof), Error>;
    
    fn mask_shuffle(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        deck: &Vec<Self::Ciphertext>,
        masking_factors: &Vec<EncryptionScheme::Randomness>,
        permutation: &Vec<usize>
    ) -> Result<Vec<Self::Ciphertext>, Error>;
}