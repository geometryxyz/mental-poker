use ark_std::rand::Rng;
use crypto_primitives::homomorphic_encryption::HomomorphicEncryptionScheme;
use utils::permutation::Permutation;

pub mod discrete_log_vtmp;
use anyhow::Result;

pub trait VerifiableThresholdMaskingProtocol<EncryptionScheme>
where
    EncryptionScheme: HomomorphicEncryptionScheme,
{
    type DecryptionKey;
    type DLEqualityProof;
    type PrivateKeyProof;

    fn setup<R: Rng>(rng: &mut R) -> Result<EncryptionScheme::Parameters>;

    fn keygen<R: Rng>(
        pp: &EncryptionScheme::Parameters,
        rng: &mut R,
    ) -> Result<(EncryptionScheme::PublicKey, EncryptionScheme::SecretKey)>;

    fn verified_keygen<R: Rng>(
        pp: &EncryptionScheme::Parameters,
        rng: &mut R,
    ) -> Result<(
        EncryptionScheme::PublicKey,
        EncryptionScheme::SecretKey,
        Self::PrivateKeyProof,
    )>;

    fn mask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        message: &EncryptionScheme::Plaintext,
        r: &EncryptionScheme::Randomness,
    ) -> Result<EncryptionScheme::Ciphertext>;

    fn verified_mask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        message: &EncryptionScheme::Plaintext,
        r: &EncryptionScheme::Randomness,
    ) -> Result<(EncryptionScheme::Ciphertext, Self::DLEqualityProof)>;

    fn compute_decryption_key(
        sk: &EncryptionScheme::SecretKey,
        ciphertext: &EncryptionScheme::Ciphertext,
    ) -> Result<Self::DecryptionKey>;

    fn unmask(
        decryption_key: &Self::DecryptionKey,
        cipher: &EncryptionScheme::Ciphertext,
    ) -> Result<EncryptionScheme::Plaintext>;

    fn remask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        ciphertext: &EncryptionScheme::Ciphertext,
        alpha: &EncryptionScheme::Randomness,
    ) -> Result<EncryptionScheme::Ciphertext>;

    fn verified_remask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        ciphertext: &EncryptionScheme::Ciphertext,
        alpha: &EncryptionScheme::Randomness,
    ) -> Result<(EncryptionScheme::Ciphertext, Self::DLEqualityProof)>;

    fn mask_shuffle(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        deck: &Vec<EncryptionScheme::Ciphertext>,
        masking_factors: &Vec<EncryptionScheme::Randomness>,
        permutation: &Permutation,
    ) -> Result<Vec<EncryptionScheme::Ciphertext>>;
}
