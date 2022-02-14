pub mod masking;
pub mod unmasking;
pub mod error;

pub mod elgamal;

use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_crypto_primitives::encryption::elgamal::*;
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_ff::{PrimeField};
use ark_std::rand::Rng;
use error::Error;
use std::marker::PhantomData;

pub struct DiscreteLogVTMF<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}


trait VerifiableThresholdMaskingProtocol<EncryptionScheme: AsymmetricEncryptionScheme> {
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

    fn remask();
    
    fn mask_shuffle();
}

impl<C: ProjectiveCurve> VerifiableThresholdMaskingProtocol<ElGamal<C>> for DiscreteLogVTMF<C> {
    type DecryptionKey = C;
    fn setup<R: Rng>(rng: &mut R) -> Result<Parameters<C>, Error> {
        match ElGamal::<C>::setup(rng) {
            Ok(parameters) => Ok(parameters),
            Err(_) => Err(Error::SetupError),
        }
    }

    fn keygen<R: Rng>(
        pp: &Parameters<C>,
        rng: &mut R,
    ) -> Result<(PublicKey<C>, SecretKey<C>), Error>{
        match ElGamal::<C>::keygen(pp, rng) {
            Ok(parameters) => Ok(parameters),
            Err(_) => Err(Error::KeyGenError),
        }   
    }

    fn verify_key_ownership() -> bool {
        true
    }

    fn mask(pp: &Parameters<C>, shared_key: &PublicKey<C>, message: &Plaintext<C>, r: &Randomness<C>) -> Result<Ciphertext<C>, Error> {
        match ElGamal::<C>::encrypt(pp, shared_key, message, r) {
            Ok(ciphertext) => Ok(ciphertext),
            Err(_) => Err(Error::MaskingError),
        } 
    }

    fn compute_decryption_key(sk: &SecretKey<C>, ciphertext: &Ciphertext<C>) -> Result<Self::DecryptionKey, Error> {
        let decryption_key = ciphertext.0.mul(sk.0.into_repr());

        Ok(decryption_key)
    }

    fn unmask(decryption_key: &Self::DecryptionKey, cipher: &Ciphertext<C>) -> Result<Plaintext<C>, Error>{
        let neg = -decryption_key.into_affine();
        let decrypted = neg + cipher.1;

        Ok(decrypted)
    }

    fn remask() {
        
    }

    fn mask_shuffle() {

    }
}


#[cfg(test)]
mod test {
    use super::{DiscreteLogVTMF, VerifiableThresholdMaskingProtocol};
    use ark_crypto_primitives::encryption::elgamal::{ElGamal, Randomness};
    use starknet_curve::{Projective};
    use ark_std::{test_rng, UniformRand};
    use rand::{thread_rng};
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;

    #[test]
    fn random_test() {
        let rng = &mut test_rng();
        let rng1 = &mut thread_rng();
        let rng2 = &mut thread_rng();
        let rng3 = &mut thread_rng();


        // setup and key generation
        let parameters = DiscreteLogVTMF::<Projective>::setup(rng).unwrap();

        let (pk1, sk1) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng1).unwrap();
        let (pk2, sk2) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng2).unwrap();
        let (pk3, sk3) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng3).unwrap();

        let msg = Projective::rand(rng).into();
        let r = Randomness::rand(rng);

        let shared_key = pk1 + pk2 + pk3;

        let cipher = ElGamal::<Projective>::encrypt(&parameters, &shared_key, &msg, &r).unwrap();

        let d1 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk1, &cipher).unwrap();
        let d2 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk2, &cipher).unwrap();
        let d3 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk3, &cipher).unwrap();

        let master_decryption_key = d1 + d2 + d3;

        let decrypted = DiscreteLogVTMF::<Projective>::unmask(&master_decryption_key, &cipher).unwrap();

        assert_eq!(decrypted, msg);
    }
}