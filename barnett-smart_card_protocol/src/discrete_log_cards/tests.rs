#[cfg(test)]
mod test {
    use crate::error::CardProtocolError;
    use crate::BarnettSmartProtocol;
    use crate::{
        discrete_log_cards,
        discrete_log_cards::{masking, remasking, reveal},
    };
    use crate::{ComputationStatement, Verifiable};

    use ark_ff::UniformRand;
    use ark_std::{rand::Rng, Zero};
    use crypto_primitives::error::CryptoError;
    use crypto_primitives::zkp::proofs::schnorr_identification;
    use crypto_primitives::zkp::ArgumentOfKnowledge;
    use rand::thread_rng;
    use std::iter::Iterator;

    // Choose elliptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Instantiate concrete type for our card protocol
    type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
    type CardParameters = discrete_log_cards::Parameters<Curve>;
    type PublicKey = discrete_log_cards::PublicKey<Curve>;
    type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;

    type Card = discrete_log_cards::Card<Curve>;
    type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
    type RevealToken = discrete_log_cards::RevealToken<Curve>;

    type KeyOwnArg = schnorr_identification::SchnorrIdentification<Curve>;
    type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;

    type MaskingProof = masking::Proof<Curve>;
    type RemaskingProof = remasking::Proof<Curve>;
    type RevealProof = reveal::Proof<Curve>;

    fn setup_players<R: Rng>(
        rng: &mut R,
        n: usize,
    ) -> (CardParameters, Vec<(PublicKey, SecretKey)>, PublicKey) {
        let parameters = CardProtocol::setup(rng).unwrap();

        let mut players: Vec<(PublicKey, SecretKey)> = Vec::with_capacity(n);
        let mut expected_shared_key = PublicKey::zero();

        for i in 0..n {
            players.push(CardProtocol::player_keygen(rng, &parameters).unwrap());
            expected_shared_key = expected_shared_key + players[i].0
        }

        (parameters, players, expected_shared_key)
    }

    #[test]
    fn generate_and_verify_key() {
        let rng = &mut thread_rng();

        let parameters = CardProtocol::setup(rng).unwrap();

        let (pk, sk) = CardProtocol::player_keygen(rng, &parameters).unwrap();

        let p1_keyproof = CardProtocol::prove_key_ownership(rng, &parameters, &pk, &sk).unwrap();

        assert_eq!(
            Ok(()),
            p1_keyproof.verify(&parameters.enc_parameters.generator, &pk)
        );

        let other_key = Scalar::rand(rng);
        let wrong_proof =
            CardProtocol::prove_key_ownership(rng, &parameters, &pk, &other_key).unwrap();

        assert_eq!(
            wrong_proof.verify(&parameters.enc_parameters.generator, &pk),
            Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification"
            )))
        )
    }

    #[test]
    fn aggregate_keys() {
        let rng = &mut thread_rng();
        let n = 10;

        let (parameters, players, expected_shared_key) = setup_players(rng, n);

        let proofs = players
            .iter()
            .map(|player| {
                KeyOwnArg::prove(
                    rng,
                    &parameters.enc_parameters.generator,
                    &player.0,
                    &player.1,
                )
                .unwrap()
            })
            .collect::<Vec<ProofKeyOwnership>>();

        let key_proof_pairs = players
            .iter()
            .zip(proofs.iter())
            .map(|(player, &proof)| (player.0, proof.clone()))
            .collect::<Vec<(PublicKey, ProofKeyOwnership)>>();

        let test_aggregate =
            CardProtocol::compute_aggregate_key(&parameters, &key_proof_pairs).unwrap();

        assert_eq!(test_aggregate, expected_shared_key);

        let mut bad_key_proof_pairs = key_proof_pairs;
        bad_key_proof_pairs[0].0 = PublicKey::zero();

        let test_fail_aggregate =
            CardProtocol::compute_aggregate_key(&parameters, &bad_key_proof_pairs);

        assert_eq!(
            test_fail_aggregate,
            Err(CardProtocolError::ProofVerificationError(
                CryptoError::ProofVerificationError(String::from("Schnorr Identification"))
            ))
        )
    }

    #[test]
    fn verify_masking() {
        let rng = &mut thread_rng();
        let n = 10;

        let (parameters, _, aggregate_key) = setup_players(rng, n);

        let some_card = Card::rand(rng);
        let some_random = Scalar::rand(rng);

        let (masked, masking_proof): (MaskedCard, MaskingProof) =
            CardProtocol::mask(rng, &parameters, &aggregate_key, &some_card, &some_random).unwrap();

        let statement = ComputationStatement::new(some_card, masked, (parameters, aggregate_key));

        assert_eq!(Ok(()), masking_proof.verify(&statement));

        let wrong_output = MaskedCard::rand(rng);
        let bad_statement =
            ComputationStatement::new(some_card, wrong_output, (parameters, aggregate_key));

        assert_eq!(
            masking_proof.verify(&bad_statement),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        )
    }

    #[test]
    fn verify_remasking() {
        let rng = &mut thread_rng();
        let n = 10;

        let (parameters, _, aggregate_key) = setup_players(rng, n);

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

        let statement =
            ComputationStatement::new(some_masked_card, remasked, (parameters, aggregate_key));

        assert_eq!(Ok(()), remasking_proof.verify(&statement));

        let wrong_output = MaskedCard::rand(rng);
        let bad_statement =
            ComputationStatement::new(some_masked_card, wrong_output, (parameters, aggregate_key));

        assert_eq!(
            remasking_proof.verify(&bad_statement),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        )
    }

    #[test]
    fn verify_reveal() {
        let rng = &mut thread_rng();

        let parameters = CardProtocol::setup(rng).unwrap();
        let (pk, sk) = CardProtocol::player_keygen(rng, &parameters).unwrap();

        let some_masked_card = MaskedCard::rand(rng);

        let (reveal_token, reveal_proof): (RevealToken, RevealProof) =
            CardProtocol::compute_reveal_token(rng, &parameters, &sk, &pk, &some_masked_card)
                .unwrap();

        let statement = ComputationStatement::new(some_masked_card, reveal_token, (parameters, pk));

        assert_eq!(Ok(()), reveal_proof.verify(&statement));

        let wrong_reveal = RevealToken::rand(rng);
        let bad_statement =
            ComputationStatement::new(some_masked_card, wrong_reveal, (parameters, pk));

        assert_eq!(
            reveal_proof.verify(&bad_statement),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        )
    }

    #[test]
    fn test_unmask() {
        let rng = &mut thread_rng();
        let n = 10;

        let (parameters, players, expected_shared_key) = setup_players(rng, n);

        let card = Card::rand(rng);
        let alpha = Scalar::rand(rng);
        let (masked, _) =
            CardProtocol::mask(rng, &parameters, &expected_shared_key, &card, &alpha).unwrap();

        let decryption_key = players
            .iter()
            .map(|player| {
                let (token, proof) = CardProtocol::compute_reveal_token(
                    rng,
                    &parameters,
                    &player.1,
                    &player.0,
                    &masked,
                )
                .unwrap();
                (token, proof, player.0)
            })
            .collect::<Vec<_>>();

        let unmasked = CardProtocol::unmask(&parameters, &decryption_key, &masked).unwrap();

        assert_eq!(card, unmasked);

        let mut bad_decryption_key = decryption_key;
        bad_decryption_key[0].0 = RevealToken::rand(rng);

        let failed_decryption = CardProtocol::unmask(&parameters, &bad_decryption_key, &masked);

        assert_eq!(
            failed_decryption,
            Err(CardProtocolError::ProofVerificationError(
                CryptoError::ProofVerificationError(String::from("Chaum-Pedersen"))
            ))
        )
    }
}
