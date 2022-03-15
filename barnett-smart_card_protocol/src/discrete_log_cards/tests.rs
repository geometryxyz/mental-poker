#[cfg(test)]
mod test {
    use crate::error::CardProtocolError;
    use crate::BarnettSmartProtocol;
    use crate::Verifiable;
    use crate::{discrete_log_cards, discrete_log_cards::{masking_arg, remasking_arg}, };

    use ark_ff::UniformRand;
    use ark_std::{rand::Rng, Zero};
    use crypto_primitives::error::CryptoError;
    use crypto_primitives::zkp::ArgumentOfKnowledge;
    use rand::thread_rng;
    use starknet_curve;
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

    type KeyOwnArg = discrete_log_cards::key_ownership::KeyOwnershipArg<Curve>;
    type ProofKeyOwnership = discrete_log_cards::ProofKeyOwnership<Curve>;

    type MaskingArg = masking_arg::MaskingArgument<Curve>;
    type MaskingProof = discrete_log_cards::ProofMasking<Curve>;

    type RemaskingArg = remasking_arg::RemaskingArgument<Curve>;

    fn setup_players<R: Rng>(
        rng: &mut R,
        n: usize,
    ) -> (CardParameters, Vec<(PublicKey, SecretKey)>, PublicKey) {
        let parameters = CardProtocol::setup(rng).unwrap();

        let mut players: Vec<(PublicKey, SecretKey)> = Vec::with_capacity(n);
        let mut expected_shared_key = PublicKey::zero();

        for i in 0..n {
            players.push(CardProtocol::player_keygen(&parameters, rng).unwrap());
            expected_shared_key = expected_shared_key + players[i].0
        }

        (parameters, players, expected_shared_key)
    }

    #[test]
    fn generate_and_verify_key() {
        let rng = &mut thread_rng();

        let parameters = CardProtocol::setup(rng).unwrap();

        let (pk, sk) = CardProtocol::player_keygen(&parameters, rng).unwrap();

        let p1_keyproof = CardProtocol::prove_key_ownership(&parameters, &pk, &sk).unwrap();

        assert_eq!(
            Ok(()),
            p1_keyproof.verify_proof(&parameters.enc_parameters.generator, &pk)
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
                KeyOwnArg::prove(&parameters.enc_parameters.generator, &player.0, &player.1)
                    .unwrap()
            })
            .collect::<Vec<ProofKeyOwnership>>();

        let key_proof_pairs = players
            .iter()
            .zip(proofs.iter())
            .map(|(player, &proof)| (player.0, proof))
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
            CardProtocol::mask(&parameters, &aggregate_key, &some_card, &some_random).unwrap();

        let crs = masking_arg::CommonReferenceString::<Curve>::new(
            parameters.enc_parameters.generator,
            aggregate_key,
        );

        let statement = masking_arg::Statement(some_card, masked);

        assert_eq!(Ok(()), MaskingArg::verify(&crs, &statement, &masking_proof))
    }

    #[test]
    fn verify_remasking() {
        let rng = &mut thread_rng();
        let n = 10;

        let (parameters, _, aggregate_key) = setup_players(rng, n);

        let some_masked_card = MaskedCard::rand(rng);
        let some_random = Scalar::rand(rng);

        let (remasked, remasking_proof): (MaskedCard, MaskingProof) =
            CardProtocol::remask(&parameters, &aggregate_key, &some_masked_card, &some_random).unwrap();

        let crs = remasking_arg::CommonReferenceString::<Curve>::new(
            parameters.enc_parameters.generator,
            aggregate_key,
        );

        let statement = remasking_arg::Statement::new(some_masked_card, remasked);

        assert_eq!(Ok(()), RemaskingArg::verify(&crs, &statement, &remasking_proof))
    }
}
