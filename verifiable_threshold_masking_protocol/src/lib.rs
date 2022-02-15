pub mod error;
pub mod discrete_log_vtmp;


use ark_std::rand::Rng;
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use error::Error;


trait HomomorphicScheme: AsymmetricEncryptionScheme {
    type ScalarField;

    fn add(
        ciphertext: &Self::Ciphertext,
        other_ciphertext: &Self::Ciphertext
    ) -> Result<Self::Ciphertext, Error>;

    fn add_in_place(
        ciphertext: &mut Self::Ciphertext,
        other_ciphertext: &Self::Ciphertext
    ) -> Result<(), Error>;

    fn mul(
        ciphertext: &Self::Ciphertext,
        scalar: &Self::ScalarField
    ) -> Result<Self::Ciphertext, Error>; 

    fn mul_in_place(
        ciphertext: &mut Self::Ciphertext,
        scalar: &Self::ScalarField
    ) -> Result<(), Error>; 
}


trait VerifiableThresholdMaskingProtocol<EncryptionScheme: HomomorphicScheme> {
    type DecryptionKey;

    fn setup<R: Rng>(rng: &mut R) -> Result<EncryptionScheme::Parameters, Error>;
    
    fn keygen<R: Rng>(
        pp: &EncryptionScheme::Parameters,
        rng: &mut R
    ) -> Result<(EncryptionScheme::PublicKey, EncryptionScheme::SecretKey), Error>;
    
    fn verify_key_ownership() -> bool;

    fn mask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        message: &EncryptionScheme::Plaintext,
        r: &EncryptionScheme::Randomness
    ) -> Result<EncryptionScheme::Ciphertext, Error>;

    fn compute_decryption_key(
        sk: &EncryptionScheme::SecretKey,
        ciphertext: &EncryptionScheme::Ciphertext
    ) -> Result<Self::DecryptionKey, Error>;

    fn unmask(
        decryption_key: &Self::DecryptionKey,
        cipher: &EncryptionScheme::Ciphertext,
    ) -> Result<EncryptionScheme::Plaintext, Error>;

    fn remask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        ciphertext: &EncryptionScheme::Ciphertext,
        alpha: &EncryptionScheme::Randomness
    ) -> Result<EncryptionScheme::Ciphertext, Error>;
    
    fn mask_shuffle(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        deck: &Vec<EncryptionScheme::Ciphertext>,
        masking_factors: &Vec<EncryptionScheme::Randomness>,
        permutation: &Vec<usize>
    ) -> Result<Vec<EncryptionScheme::Ciphertext>, Error>;
}