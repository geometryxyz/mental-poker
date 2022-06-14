use crate::discrete_log_cards::MaskedCard;
use crate::error::CardProtocolError;
use crate::{Mask, Remask};

use ark_ec::ProjectiveCurve;
use ark_ff::Zero;
use proof_essentials::homomorphic_encryption::{el_gamal, el_gamal::ElGamal};

impl<C: ProjectiveCurve> Remask<C::ScalarField, ElGamal<C>> for MaskedCard<C> {
    fn remask(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        alpha: &C::ScalarField,
    ) -> Result<el_gamal::Ciphertext<C>, CardProtocolError> {
        let zero = el_gamal::Plaintext::zero();
        let masking_point = zero.mask(pp, shared_key, alpha)?;
        let remasked_cipher = *self + masking_point;

        Ok(remasked_cipher)
    }
}

#[cfg(test)]
mod test {
    use crate::discrete_log_cards;
    use crate::BarnettSmartProtocol;

    use ark_ff::UniformRand;
    use ark_std::{rand::Rng, Zero};
    use proof_essentials::error::CryptoError;
    use proof_essentials::zkp::proofs::chaum_pedersen_dl_equality;
    use rand::thread_rng;

    // Choose elliptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Instantiate concrete type for our card protocol
    type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
    type CardParameters = discrete_log_cards::Parameters<Curve>;
    type PublicKey = discrete_log_cards::PublicKey<Curve>;
    type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;

    type MaskedCard = discrete_log_cards::MaskedCard<Curve>;

    type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

    fn setup_players<R: Rng>(
        rng: &mut R,
        parameters: &CardParameters,
        num_of_players: usize,
    ) -> (Vec<(PublicKey, SecretKey)>, PublicKey) {
        let mut players: Vec<(PublicKey, SecretKey)> = Vec::with_capacity(num_of_players);
        let mut expected_shared_key = PublicKey::zero();

        for i in 0..parameters.n {
            players.push(CardProtocol::player_keygen(rng, &parameters).unwrap());
            expected_shared_key = expected_shared_key + players[i].0
        }

        (players, expected_shared_key)
    }

    #[test]
    fn test_verify_remasking() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let num_of_players = 10;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (_, aggregate_key) = setup_players(rng, &parameters, num_of_players);

        let some_masked_card = MaskedCard::rand(rng);
        let some_random = Scalar::rand(rng);

        let (remasked, remasking_proof): (MaskedCard, RemaskingProof) = CardProtocol::remask(
            rng,
            &parameters,
            &aggregate_key,
            &some_masked_card,
            &some_random,
        )
        .unwrap();

        assert_eq!(
            Ok(()),
            CardProtocol::verify_remask(
                &parameters,
                &aggregate_key,
                &some_masked_card,
                &remasked,
                &remasking_proof
            )
        );

        let wrong_output = MaskedCard::rand(rng);

        assert_eq!(
            CardProtocol::verify_remask(
                &parameters,
                &aggregate_key,
                &some_masked_card,
                &wrong_output,
                &remasking_proof
            ),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        )
    }
}
