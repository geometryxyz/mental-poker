pub mod error;
pub mod discrete_log_vtmp;
pub mod chaum_pedersen_dl_equality;

use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_std::rand::Rng;
use error::Error;


// trait HomomorphicScheme: AsymmetricEncryptionScheme {
//     type ScalarField;

//     fn add(
//         ciphertext: &Self::Ciphertext,
//         other_ciphertext: &Self::Ciphertext
//     ) -> Result<Self::Ciphertext, Error>;

//     fn add_in_place(
//         ciphertext: &mut Self::Ciphertext,
//         other_ciphertext: &Self::Ciphertext
//     ) -> Result<(), Error>;

//     fn mul(
//         ciphertext: &Self::Ciphertext,
//         scalar: &Self::ScalarField
//     ) -> Result<Self::Ciphertext, Error>; 

//     fn mul_in_place(
//         ciphertext: &mut Self::Ciphertext,
//         scalar: &Self::ScalarField
//     ) -> Result<(), Error>; 
// }


trait VerifiableThresholdMaskingProtocol<EncryptionScheme: AsymmetricEncryptionScheme> {
    type DecryptionKey;
    type ScalarField;
    type Ciphertext;
    type DLProof;

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
    ) -> Result<Self::Ciphertext, Error>;

    fn verified_mask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        message: &EncryptionScheme::Plaintext,
        r: &EncryptionScheme::Randomness
    ) -> Result<(Self::Ciphertext, Self::DLProof), Error>;

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
    ) -> Result<(Self::Ciphertext, Self::DLProof), Error>;
    
    fn mask_shuffle(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        deck: &Vec<Self::Ciphertext>,
        masking_factors: &Vec<EncryptionScheme::Randomness>,
        permutation: &Vec<usize>
    ) -> Result<Vec<Self::Ciphertext>, Error>;

    //CONSIDER MOVING IT TO DIFFERENT TRAIT OR OVERLOADING OPERATORS
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