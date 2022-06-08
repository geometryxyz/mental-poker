use crate::discrete_log_cards::RevealToken;
use crate::error::CardProtocolError;
use crate::Reveal;

use ark_ec::ProjectiveCurve;
use ark_ff::One;
use proof_essentials::homomorphic_encryption::{el_gamal, el_gamal::ElGamal};

impl<C: ProjectiveCurve> Reveal<C::ScalarField, ElGamal<C>> for RevealToken<C> {
    fn reveal(
        &self,
        cipher: &el_gamal::Ciphertext<C>,
    ) -> Result<el_gamal::Plaintext<C>, CardProtocolError> {
        let neg_one = -C::ScalarField::one();
        let negative_token = *self * neg_one;
        let decrypted = negative_token + el_gamal::Plaintext(cipher.1);

        Ok(decrypted)
    }
}

#[cfg(test)]
mod test {
    use crate::discrete_log_cards;
    use crate::BarnettSmartProtocol;

    use ark_ff::UniformRand;
    use proof_essentials::error::CryptoError;
    use proof_essentials::zkp::proofs::chaum_pedersen_dl_equality;
    use rand::thread_rng;

    // Choose elliptic curve setting
    type Curve = starknet_curve::Projective;

    // Instantiate concrete type for our card protocol
    type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;

    type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
    type RevealToken = discrete_log_cards::RevealToken<Curve>;

    type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

    #[test]
    fn test_verify_reveal() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (pk, sk) = CardProtocol::player_keygen(rng, &parameters).unwrap();

        let some_masked_card = MaskedCard::rand(rng);

        let (reveal_token, reveal_proof): (RevealToken, RevealProof) =
            CardProtocol::compute_reveal_token(rng, &parameters, &sk, &pk, &some_masked_card)
                .unwrap();

        assert_eq!(
            Ok(()),
            CardProtocol::verify_reveal(
                &parameters,
                &pk,
                &reveal_token,
                &some_masked_card,
                &reveal_proof
            )
        );

        let wrong_reveal = RevealToken::rand(rng);

        assert_eq!(
            CardProtocol::verify_reveal(
                &parameters,
                &pk,
                &wrong_reveal,
                &some_masked_card,
                &reveal_proof
            ),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        )
    }
}
