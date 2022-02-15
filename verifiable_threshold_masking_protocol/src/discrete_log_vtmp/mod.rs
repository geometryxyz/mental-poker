use crate::*;

pub mod tests;

use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_crypto_primitives::encryption::{AsymmetricEncryptionScheme, elgamal::*};
use ark_ff::{PrimeField};
use ark_std::Zero;
use ark_std::rand::Rng;
use std::marker::PhantomData;
use std::iter::Iterator;


pub struct DiscreteLogVTMF<C: ProjectiveCurve>  {
    _group: PhantomData<C>
}


impl<C: ProjectiveCurve> HomomorphicScheme for ElGamal<C> {
    type ScalarField = C::ScalarField;

    fn add(ciphertext: &Self::Ciphertext, other_ciphertext: &Self::Ciphertext) -> Result<Self::Ciphertext, Error> {
        let ciphertext = (ciphertext.0 + other_ciphertext.0, ciphertext.1 + other_ciphertext.1);

        Ok(ciphertext)
    }

    fn add_in_place(ciphertext: &mut Self::Ciphertext, other_ciphertext: &Self::Ciphertext) -> Result<(), Error> {
        ciphertext.0 = ciphertext.0 + other_ciphertext.0;
        ciphertext.1 = ciphertext.1 + other_ciphertext.1;

        Ok(())
    }

    fn mul(
        ciphertext: &Self::Ciphertext,
        scalar: &Self::ScalarField
    ) -> Result<Self::Ciphertext, Error> {
        let multiplied = (ciphertext.0.mul(scalar.into_repr()).into_affine(), ciphertext.0.mul(scalar.into_repr()).into_affine());

        Ok(multiplied)
    }

    fn mul_in_place(
        ciphertext: &mut Self::Ciphertext,
        scalar: &Self::ScalarField
    ) -> Result<(), Error> {
        ciphertext.0 = ciphertext.0.mul(scalar.into_repr()).into_affine();
        ciphertext.1 = ciphertext.0.mul(scalar.into_repr()).into_affine();

        Ok(())
    }
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

    fn remask(
        pp: &Parameters<C>,
        shared_key: &PublicKey<C>,
        ciphertext: &Ciphertext<C>,
        alpha: &Randomness<C>,
    ) -> Result<Ciphertext<C>, Error> {
        let masking_point = Self::mask(pp, shared_key, &C::Affine::zero(), alpha).unwrap();
        let output_point = ElGamal::<C>::add(ciphertext, &masking_point).unwrap();
        
        Ok(output_point)
    }

    fn mask_shuffle(
        pp: &Parameters<C>,
        shared_key: &PublicKey<C>,
        deck: &Vec<Ciphertext<C>>,
        masking_factors: &Vec<Randomness<C>>,
        permutation: &Vec<usize>,
    ) -> Result<Vec<Ciphertext<C>>, Error> {
        let permuted_deck = masking_factors.iter().enumerate().map(|(i, masking_factor)| {
            let index = permutation[i];
            let card = deck[index];

            Self::remask(pp, shared_key, &card, masking_factor).unwrap()

        }).collect::<Vec<_>>();

        Ok(permuted_deck)
    }
}