use crate::*;

pub mod tests;

use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_crypto_primitives::encryption::{AsymmetricEncryptionScheme, elgamal::*, elgamal::{Ciphertext as ElGamalCipher}};
use ark_ff::{PrimeField};
use ark_std::{Zero, One};
use ark_std::rand::Rng;
use std::marker::PhantomData;
use std::iter::Iterator;
use chaum_pedersen_dl_equality::{Parameters as ChaumPedersenParameters, proof::Proof, prover::Prover};

pub struct DiscreteLogVTMF<C: ProjectiveCurve>  {
    _group: PhantomData<C>
}

pub type Ciphertext<C> = ElGamalCipher<C>;

impl<C: ProjectiveCurve> VerifiableThresholdMaskingProtocol<ElGamal<C>> for DiscreteLogVTMF<C> {
    type DecryptionKey = C;
    type ScalarField = C::ScalarField;
    type Ciphertext = Ciphertext<C>;
    type DLProof = Proof<C>;
    
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

    fn mask(pp: &Parameters<C>, shared_key: &PublicKey<C>, message: &Plaintext<C>, r: &Randomness<C>) -> Result<Self::Ciphertext, Error> {
        match ElGamal::<C>::encrypt(pp, shared_key, message, r) {
            Ok(ciphertext) => Ok(ciphertext),
            Err(_) => Err(Error::MaskingError),
        } 
    }

    fn verified_mask(
        pp: &Parameters<C>,
        shared_key: &PublicKey<C>,
        message: &Plaintext<C>,
        r: &Randomness<C>
    ) -> Result<(Self::Ciphertext, Self::DLProof), Error> {
        let ciphertext = Self::mask(&pp, &shared_key, &message, &r).unwrap();

        let proof_parameters = ChaumPedersenParameters {
            g: pp.generator,
            h: *shared_key,
        };
        let negative_message = message.mul(-C::ScalarField::one());
        let statement = (ciphertext.0, negative_message.add_mixed(&ciphertext.1).into_affine());
        let proof = Prover::<C>::create_proof(&proof_parameters, &statement, r.0);
        Ok((ciphertext, proof))    
    }

    fn compute_decryption_key(sk: &SecretKey<C>, ciphertext: &Self::Ciphertext) -> Result<Self::DecryptionKey, Error> {
        let decryption_key = ciphertext.0.mul(sk.0.into_repr());

        Ok(decryption_key)
    }

    fn unmask(decryption_key: &Self::DecryptionKey, cipher: &Self::Ciphertext) -> Result<Plaintext<C>, Error>{
        let neg = -decryption_key.into_affine();
        let decrypted = neg + cipher.1;

        Ok(decrypted)
    }

    fn remask(
        pp: &Parameters<C>,
        shared_key: &PublicKey<C>,
        ciphertext: &Self::Ciphertext,
        alpha: &Randomness<C>,
    ) -> Result<Self::Ciphertext, Error> {
        let masking_point = Self::mask(pp, shared_key, &C::Affine::zero(), alpha).unwrap();
        let remasked_cipher = Self::add(ciphertext, &masking_point).unwrap();
        
        Ok(remasked_cipher)
    }

    fn verified_remask(
        pp: &Parameters<C>,
        shared_key: &PublicKey<C>,
        ciphertext: &Self::Ciphertext,
        alpha: &Randomness<C>
    ) -> Result<(Self::Ciphertext, Self::DLProof), Error> {
        
        let masking_point = Self::mask(pp, shared_key, &C::Affine::zero(), alpha).unwrap();
        let remasked_cipher = Self::add(ciphertext, &masking_point).unwrap();

        let proof_parameters = ChaumPedersenParameters {
            g: pp.generator,
            h: *shared_key,
        };
        let neg_one = -C::ScalarField::one();
        let negative_cipher = Self::mul(&ciphertext, &neg_one).unwrap();
        let statement = Self::add(&remasked_cipher, &negative_cipher).unwrap();

        let proof = Prover::<C>::create_proof(&proof_parameters, &statement, alpha.0);
        
        Ok((remasked_cipher, proof))   
    }

    fn mask_shuffle(
        pp: &Parameters<C>,
        shared_key: &PublicKey<C>,
        deck: &Vec<Self::Ciphertext>,
        masking_factors: &Vec<Randomness<C>>,
        permutation: &Vec<usize>,
    ) -> Result<Vec<Self::Ciphertext>, Error> {
        let permuted_deck = masking_factors.iter().enumerate().map(|(i, masking_factor)| {
            let index = permutation[i];
            let card = deck[index];

            Self::remask(pp, shared_key, &card, masking_factor).unwrap()

        }).collect::<Vec<_>>();

        Ok(permuted_deck)
    }

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
        let multiplied = (ciphertext.0.mul(scalar.into_repr()).into_affine(), ciphertext.1.mul(scalar.into_repr()).into_affine());

        Ok(multiplied)
    }

    fn mul_in_place(
        ciphertext: &mut Self::Ciphertext,
        scalar: &Self::ScalarField
    ) -> Result<(), Error> {
        ciphertext.0 = ciphertext.0.mul(scalar.into_repr()).into_affine();
        ciphertext.1 = ciphertext.1.mul(scalar.into_repr()).into_affine();

        Ok(())
    }


}