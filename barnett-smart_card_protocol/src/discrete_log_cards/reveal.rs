use crate::discrete_log_cards::{MaskedCard, Parameters, PlayerSecretKey, PublicKey, RevealToken};
use crate::error::CardProtocolError;
use crate::{ComputationStatement, Provable, Reveal, Verifiable};

use ark_ec::ProjectiveCurve;
use ark_ff::One;
use ark_std::rand::Rng;
use crypto_primitives::error::CryptoError;
use crypto_primitives::homomorphic_encryption::{el_gamal, el_gamal::ElGamal};
use std::ops::Mul;

use crypto_primitives::zkp::{proofs::chaum_pedersen_dl_equality, ArgumentOfKnowledge};

impl<C: ProjectiveCurve> Reveal<C::ScalarField, ElGamal<C>> for RevealToken<C> {
    fn reveal(
        &self,
        cipher: &el_gamal::Ciphertext<C>,
    ) -> Result<el_gamal::Plaintext<C>, CardProtocolError> {
        let neg_one = -C::ScalarField::one();
        let negative_token = self.mul(neg_one);
        let decrypted = negative_token + el_gamal::Plaintext(cipher.1);

        Ok(decrypted)
    }
}

pub type Statement<C> =
    ComputationStatement<MaskedCard<C>, RevealToken<C>, (Parameters<C>, PublicKey<C>)>;

impl<C: ProjectiveCurve> Statement<C> {
    pub fn to_chaum_pedersen(
        &self,
    ) -> (
        chaum_pedersen_dl_equality::Parameters<C>,
        chaum_pedersen_dl_equality::Statement<C>,
    ) {
        // Unwrap the statement about cards
        let masked_card = self.input;
        let token = self.output;
        let parameters = self.public_parameters.0;
        let player_public_key = self.public_parameters.1;

        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(
            masked_card.0,
            parameters.enc_parameters.generator,
        );

        // Map to Chaum-Pedersen parameters
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(token.0, player_public_key);

        (cp_parameters, cp_statement)
    }
}

pub struct Proof<C: ProjectiveCurve>(pub chaum_pedersen_dl_equality::proof::Proof<C>);

impl<C: ProjectiveCurve> Provable<chaum_pedersen_dl_equality::DLEquality<C>> for Statement<C> {
    type Output = Proof<C>;
    type Witness = PlayerSecretKey<C>;

    fn prove<R: Rng>(
        &self,
        rng: &mut R,
        witness: Self::Witness,
    ) -> Result<Self::Output, CryptoError> {
        let (cp_parameters, cp_statement) = self.to_chaum_pedersen();

        // Use witness to prove the statement
        let cp_proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            &witness,
        )?;

        Ok(Proof(cp_proof))
    }
}

impl<C: ProjectiveCurve> Verifiable<chaum_pedersen_dl_equality::DLEquality<C>> for Proof<C> {
    type Statement = Statement<C>;

    fn verify(&self, statement: &Self::Statement) -> Result<(), CryptoError> {
        let (cp_parameters, cp_statement) = statement.to_chaum_pedersen();

        chaum_pedersen_dl_equality::DLEquality::verify(&cp_parameters, &cp_statement, &self.0)
    }
}
