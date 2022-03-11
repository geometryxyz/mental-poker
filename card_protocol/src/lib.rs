use ark_ff::Field;
use ark_std::rand::Rng;
use crypto_primitives::homomorphic_encryption::HomomorphicEncryptionScheme;
use crypto_primitives::utils::permutation::Permutation;
use crypto_primitives::vector_commitment::HomomorphicCommitmentScheme;
use crypto_primitives::zkp::ArgumentOfKnowledge;

pub mod discrete_log_vtmp;
use anyhow::Result;

pub trait CardGameProtocol<F, Enc, Comm, DLKnowledge, DLEquality>
where
    F: Field,
    Enc: HomomorphicEncryptionScheme<F>,
    Comm: HomomorphicCommitmentScheme<F>,
    DLKnowledge: ArgumentOfKnowledge,
    DLEquality: ArgumentOfKnowledge,
{
    type DecryptionKey;

    fn setup<R: Rng>(rng: &mut R) -> Result<Enc::Parameters>;

    fn keygen<R: Rng>(
        pp: &Enc::Parameters,
        rng: &mut R,
    ) -> Result<(Enc::PublicKey, Enc::SecretKey)>;

    fn verified_keygen<R: Rng>(
        pp: &Enc::Parameters,
        rng: &mut R,
    ) -> Result<(Enc::PublicKey, Enc::SecretKey, DLKnowledge::Proof)>;

    fn mask(
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        message: &Enc::Plaintext,
        r: &Enc::Randomness,
    ) -> Result<Enc::Ciphertext>;

    fn verified_mask(
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        message: &Enc::Plaintext,
        r: &Enc::Randomness,
    ) -> Result<(Enc::Ciphertext, DLEquality::Proof)>;

    fn compute_decryption_key(
        sk: &Enc::SecretKey,
        ciphertext: &Enc::Ciphertext,
    ) -> Result<Self::DecryptionKey>;

    fn unmask(
        decryption_key: &Self::DecryptionKey,
        cipher: &Enc::Ciphertext,
    ) -> Result<Enc::Plaintext>;

    fn remask(
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        ciphertext: &Enc::Ciphertext,
        alpha: &Enc::Randomness,
    ) -> Result<Enc::Ciphertext>;

    fn verified_remask(
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        ciphertext: &Enc::Ciphertext,
        alpha: &Enc::Randomness,
    ) -> Result<(Enc::Ciphertext, DLEquality::Proof)>;

    fn mask_shuffle(
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        deck: &Vec<Enc::Ciphertext>,
        masking_factors: &Vec<Enc::Randomness>,
        permutation: &Permutation,
    ) -> Result<Vec<Enc::Ciphertext>>;
}
