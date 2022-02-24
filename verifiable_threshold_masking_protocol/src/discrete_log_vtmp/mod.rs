pub mod tests;

use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_crypto_primitives::encryption::{AsymmetricEncryptionScheme, elgamal::*, elgamal::{Ciphertext}};
use ark_ff::{PrimeField};
use ark_std::{Zero, One, io::{Write, Read}};
use ark_std::rand::Rng;
use std::marker::PhantomData;
use std::iter::Iterator;
use crate::chaum_pedersen_dl_equality::{Parameters as ChaumPedersenParameters, proof::Proof as ChaumPedersenProof, prover::Prover as ChaumPedersenProver};
use crate::schnorr_identification::{Parameters as SchnorrParameters, proof::Proof as SchnorrProof, prover::Prover as SchnorrProver};
use crate::error::Error;
use ark_serialize::{CanonicalSerialize, SerializationError, CanonicalDeserialize};

// use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
// use ark_std::rand::Rng;
// use error::Error;
use std::ops::{Add, Mul};

pub trait VerifiableThresholdMaskingProtocol<EncryptionScheme: AsymmetricEncryptionScheme> {
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

pub struct DiscreteLogVTMF<C: ProjectiveCurve>  {
    _group: PhantomData<C>
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ElgamalCipher<C: ProjectiveCurve>(
    pub C::Affine,
    pub C::Affine,
);

impl<C: ProjectiveCurve> Zero for ElgamalCipher<C> {
    fn zero() -> ElgamalCipher<C> {
        ElgamalCipher::<C>(C::Affine::zero(), C::Affine::zero())
    }

    fn is_zero(&self) -> bool {
        *self == ElgamalCipher::<C>(C::Affine::zero(), C::Affine::zero())
    }
}

impl<C: ProjectiveCurve> From<Ciphertext<C>> for ElgamalCipher<C> {
    fn from(ciphertext: Ciphertext<C>) -> Self {
        ElgamalCipher::<C>(ciphertext.0, ciphertext.1)
    }
}

impl<C: ProjectiveCurve> std::ops::Add<ElgamalCipher<C>> for ElgamalCipher<C> {
    type Output = ElgamalCipher<C>;

    fn add(self, _rhs: ElgamalCipher<C>) -> ElgamalCipher<C> {
        ElgamalCipher::<C>(self.0 + _rhs.0, self.1 + _rhs.1)
    }
}


impl<C: ProjectiveCurve> std::iter::Sum for ElgamalCipher<C> {
    fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
        iter.fold(
            ElgamalCipher::<C>(C::Affine::zero(), C::Affine::zero()),
            |a, b| a + b,
        )
    }
}

impl<C: ProjectiveCurve> std::ops::Mul<C::ScalarField> for ElgamalCipher<C> {
    type Output = ElgamalCipher<C>;

    fn mul(self, scalar: C::ScalarField) -> ElgamalCipher<C> {
        ElgamalCipher::<C>(self.0.mul(scalar).into_affine(), self.1.mul(scalar).into_affine())
    }
}

impl<C: ProjectiveCurve> CanonicalSerialize for ElgamalCipher<C> {
    #[inline]
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.0.serialize(&mut writer)?;
        self.1.serialize(writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.0.serialized_size() + self.1.serialized_size()
    }

    #[inline]
    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.0.serialize_uncompressed(&mut writer)?;
        self.1.serialize_uncompressed(writer)?;
        Ok(())
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        self.0.uncompressed_size() + self.1.uncompressed_size()
    }
}

impl<C: ProjectiveCurve> CanonicalDeserialize for ElgamalCipher<C> {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let c0 = C::Affine::deserialize(&mut reader)?;
        let c1 = C::Affine::deserialize(&mut reader)?;
        
        Ok(Self(c0, c1))
    }

    fn deserialize_uncompressed<R: Read>(
        mut reader: R,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let c0 = C::Affine::deserialize_uncompressed(&mut reader)?;
        let c1 = C::Affine::deserialize_uncompressed(&mut reader)?;
        
        Ok(Self(c0, c1))
    }

    fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let c0 = C::Affine::deserialize_unchecked(&mut reader)?;
        let c1 = C::Affine::deserialize_unchecked(&mut reader)?;
        
        Ok(Self(c0, c1))
    }
}


impl<C: ProjectiveCurve> VerifiableThresholdMaskingProtocol<ElGamal<C>> for DiscreteLogVTMF<C> {
    type DecryptionKey = C;
    type ScalarField = C::ScalarField;
    type Ciphertext = ElgamalCipher<C>;
    type DLEqualityProof = ChaumPedersenProof<C>;
    type PrivateKeyProof = SchnorrProof<C>;
    
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

    fn verified_keygen<R: Rng>(
        pp: &Parameters<C>,
        rng: &mut R
    ) -> Result<(PublicKey<C>, SecretKey<C>, Self::PrivateKeyProof), Error> {
        match ElGamal::<C>::keygen(pp, rng) {
            Ok(parameters) => {
                let (pk, sk) = parameters;

                let params = SchnorrParameters {
                    generator: pp.generator
                };

                let proof = SchnorrProver::<C>::create_proof(&params, &pk, sk.0);
                
                Ok((pk, sk, proof))
            },
            Err(_) => Err(Error::KeyGenError),
        }   
    }

    fn mask(pp: &Parameters<C>, shared_key: &PublicKey<C>, message: &Plaintext<C>, r: &Randomness<C>) -> Result<Self::Ciphertext, Error> {
        match ElGamal::<C>::encrypt(pp, shared_key, message, r) {
            Ok(ciphertext) => Ok(ciphertext.into()),
            Err(_) => Err(Error::MaskingError),
        } 
    }

    fn verified_mask(
        pp: &Parameters<C>,
        shared_key: &PublicKey<C>,
        message: &Plaintext<C>,
        r: &Randomness<C>
    ) -> Result<(Self::Ciphertext, Self::DLEqualityProof), Error> {
        let ciphertext = Self::mask(&pp, &shared_key, &message, &r).unwrap();

        let proof_parameters = ChaumPedersenParameters {
            g: pp.generator,
            h: *shared_key,
        };
        let negative_message = message.mul(-C::ScalarField::one());
        let statement = (ciphertext.0, negative_message.add_mixed(&ciphertext.1).into_affine());
        let proof = ChaumPedersenProver::<C>::create_proof(&proof_parameters, &statement.into(), r.0);
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
        let remasked_cipher = *ciphertext + masking_point;
        
        Ok(remasked_cipher)
    }

    fn verified_remask(
        pp: &Parameters<C>,
        shared_key: &PublicKey<C>,
        ciphertext: &Self::Ciphertext,
        alpha: &Randomness<C>
    ) -> Result<(Self::Ciphertext, Self::DLEqualityProof), Error> {
        
        let masking_point = Self::mask(pp, shared_key, &C::Affine::zero(), alpha).unwrap();
        let remasked_cipher = *ciphertext + masking_point;

        let proof_parameters = ChaumPedersenParameters {
            g: pp.generator,
            h: *shared_key,
        };
        let neg_one = -C::ScalarField::one();
        let negative_cipher = *ciphertext * neg_one;
        let statement = remasked_cipher + negative_cipher;

        let proof = ChaumPedersenProver::<C>::create_proof(&proof_parameters, &statement, alpha.0);
        
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
}

#[cfg(test)]
mod test {

    use super::*;
    use starknet_curve::{Projective};
    use ark_std::{UniformRand};
    use rand::thread_rng;

    #[test]
    fn serialize_unserialize_test() {
        let mut rng = thread_rng();
        let c0 = Projective::rand(&mut rng).into_affine();
        let c1 = Projective::rand(&mut rng).into_affine();

        let cipher = ElgamalCipher::<Projective>(c0, c1);

        let mut serialized = vec![0; cipher.serialized_size()];
        cipher.serialize(&mut serialized[..]).unwrap();

        let deserialized = ElgamalCipher::<Projective>::deserialize(&serialized[..]).unwrap();
        assert_eq!(cipher, deserialized);
    }
}