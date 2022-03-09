pub mod tests;

use crate::chaum_pedersen_dl_equality::{
    proof::Proof as ChaumPedersenProof, prover::Prover as ChaumPedersenProver,
    Parameters as ChaumPedersenParameters,
};
use crate::error::Error;
use crate::schnorr_identification::{
    proof::Proof as SchnorrProof, prover::Prover as SchnorrProver, Parameters as SchnorrParameters,
};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;
use ark_std::{
    io::{Read, Write},
    One, Zero,
};
use std::iter::Iterator;
use std::marker::PhantomData;
use std::ops::{Add, Mul};
use crypto_primitives::homomorphic_encryption::{HomomorphicEncryptionScheme, el_gamal, el_gamal::ElGamal, MulByScalar};

pub trait VerifiableThresholdMaskingProtocol<EncryptionScheme: HomomorphicEncryptionScheme> {
    type DecryptionKey;
    type DLEqualityProof;
    type PrivateKeyProof;

    fn setup<R: Rng>(rng: &mut R) -> Result<EncryptionScheme::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &EncryptionScheme::Parameters,
        rng: &mut R,
    ) -> Result<(EncryptionScheme::PublicKey, EncryptionScheme::SecretKey), Error>;

    fn verified_keygen<R: Rng>(
        pp: &EncryptionScheme::Parameters,
        rng: &mut R,
    ) -> Result<
        (
            EncryptionScheme::PublicKey,
            EncryptionScheme::SecretKey,
            Self::PrivateKeyProof,
        ),
        Error,
    >;

    fn mask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        message: &EncryptionScheme::Plaintext,
        r: &EncryptionScheme::Randomness,
    ) -> Result<EncryptionScheme::Ciphertext, Error>;

    fn verified_mask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        message: &EncryptionScheme::Plaintext,
        r: &EncryptionScheme::Randomness,
    ) -> Result<(EncryptionScheme::Ciphertext, Self::DLEqualityProof), Error>;

    fn compute_decryption_key(
        sk: &EncryptionScheme::SecretKey,
        ciphertext: &EncryptionScheme::Ciphertext,
    ) -> Result<Self::DecryptionKey, Error>;

    fn unmask(
        decryption_key: &Self::DecryptionKey,
        cipher: &EncryptionScheme::Ciphertext,
    ) -> Result<EncryptionScheme::Plaintext, Error>;

    fn remask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        ciphertext: &EncryptionScheme::Ciphertext,
        alpha: &EncryptionScheme::Randomness,
    ) -> Result<EncryptionScheme::Ciphertext, Error>;

    fn verified_remask(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        ciphertext: &EncryptionScheme::Ciphertext,
        alpha: &EncryptionScheme::Randomness,
    ) -> Result<(EncryptionScheme::Ciphertext, Self::DLEqualityProof), Error>;

    fn mask_shuffle(
        pp: &EncryptionScheme::Parameters,
        shared_key: &EncryptionScheme::PublicKey,
        deck: &Vec<EncryptionScheme::Ciphertext>,
        masking_factors: &Vec<EncryptionScheme::Randomness>,
        permutation: &Vec<usize>,
    ) -> Result<Vec<EncryptionScheme::Ciphertext>, Error>;
}

pub struct DiscreteLogVTMF<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

impl<C: ProjectiveCurve> VerifiableThresholdMaskingProtocol<ElGamal<C>> for DiscreteLogVTMF<C> {
    type DecryptionKey = C;
    type DLEqualityProof = ChaumPedersenProof<C>;
    type PrivateKeyProof = SchnorrProof<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<el_gamal::Parameters<C>, Error> {
        match ElGamal::<C>::setup(rng) {
            Ok(parameters) => Ok(parameters),
            Err(_) => Err(Error::SetupError),
        }
    }

    fn keygen<R: Rng>(
        pp: &el_gamal::Parameters<C>,
        rng: &mut R,
    ) -> Result<(el_gamal::PublicKey<C>, el_gamal::SecretKey<C>), Error> {
        match ElGamal::<C>::keygen(pp, rng) {
            Ok(parameters) => Ok(parameters),
            Err(_) => Err(Error::KeyGenError),
        }
    }

    fn verified_keygen<R: Rng>(
        pp: &el_gamal::Parameters<C>,
        rng: &mut R,
    ) -> Result<(el_gamal::PublicKey<C>, el_gamal::SecretKey<C>, Self::PrivateKeyProof), Error> {
        match ElGamal::<C>::keygen(pp, rng) {
            Ok(parameters) => {
                let (pk, sk) = parameters;

                let params = SchnorrParameters {
                    generator: pp.generator,
                };

                let proof = SchnorrProver::<C>::create_proof(&params, &pk, sk);

                Ok((pk, sk, proof))
            }
            Err(_) => Err(Error::KeyGenError),
        }
    }

    fn mask(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        message: &el_gamal::Plaintext<C>,
        r: &el_gamal::Randomness<C>,
    ) -> Result<el_gamal::Ciphertext<C>, Error> {
        match ElGamal::<C>::encrypt(pp, shared_key, message, r) {
            Ok(ciphertext) => Ok(ciphertext.into()),
            Err(_) => Err(Error::MaskingError),
        }
    }

    fn verified_mask(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        message: &el_gamal::Plaintext<C>,
        r: &el_gamal::Randomness<C>,
    ) -> Result<(el_gamal::Ciphertext<C>, Self::DLEqualityProof), Error> {
        let ciphertext = Self::mask(&pp, &shared_key, &message, &r).unwrap();

        let proof_parameters = ChaumPedersenParameters {
            g: pp.generator,
            h: *shared_key,
        };
        let negative_message = message.mul(-C::ScalarField::one());
        let statement = (
            ciphertext.0,
            negative_message.add_mixed(&ciphertext.1).into_affine(),
        );
        let proof =
            ChaumPedersenProver::<C>::create_proof(&proof_parameters, &statement.into(), *r);
        Ok((ciphertext, proof))
    }

    fn compute_decryption_key(
        sk: &el_gamal::SecretKey<C>,
        ciphertext: &el_gamal::Ciphertext<C>,
    ) -> Result<Self::DecryptionKey, Error> {
        let decryption_key = ciphertext.0.mul(sk.into_repr());

        Ok(decryption_key)
    }

    fn unmask(
        decryption_key: &Self::DecryptionKey,
        cipher: &el_gamal::Ciphertext<C>,
    ) -> Result<el_gamal::Plaintext<C>, Error> {
        let neg = -decryption_key.into_affine();
        let decrypted = neg + cipher.1;

        Ok(decrypted)
    }

    fn remask(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        ciphertext: &el_gamal::Ciphertext<C>,
        alpha: &el_gamal::Randomness<C>,
    ) -> Result<el_gamal::Ciphertext<C>, Error> {
        let masking_point = Self::mask(pp, shared_key, &C::Affine::zero(), alpha).unwrap();
        let remasked_cipher = *ciphertext + masking_point;

        Ok(remasked_cipher)
    }

    fn verified_remask(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        ciphertext: &el_gamal::Ciphertext<C>,
        alpha: &el_gamal::Randomness<C>,
    ) -> Result<(el_gamal::Ciphertext<C>, Self::DLEqualityProof), Error> {
        let masking_point = Self::mask(pp, shared_key, &C::Affine::zero(), alpha).unwrap();
        let remasked_cipher = *ciphertext + masking_point;

        let proof_parameters = ChaumPedersenParameters {
            g: pp.generator,
            h: *shared_key,
        };
        let neg_one = -C::ScalarField::one();
        let negative_cipher = ciphertext.mul(neg_one);
        let statement = remasked_cipher + negative_cipher;

        let proof = ChaumPedersenProver::<C>::create_proof(&proof_parameters, &statement, alpha);

        Ok((remasked_cipher, proof))
    }

    fn mask_shuffle(
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        deck: &Vec<el_gamal::Ciphertext<C>>,
        masking_factors: &Vec<el_gamal::Randomness<C>>,
        permutation: &Vec<usize>,
    ) -> Result<Vec<el_gamal::Ciphertext<C>>, Error> {
        let permuted_deck = masking_factors
            .iter()
            .enumerate()
            .map(|(i, masking_factor)| {
                let index = permutation[i];
                let card = deck[index];

                Self::remask(pp, shared_key, &card, masking_factor).unwrap()
            })
            .collect::<Vec<_>>();

        Ok(permuted_deck)
    }
}
