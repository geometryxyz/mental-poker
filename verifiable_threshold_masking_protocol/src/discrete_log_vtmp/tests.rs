#[cfg(test)]
mod test {
    use crate::chaum_pedersen_dl_equality::Parameters;
    use crate::discrete_log_vtmp::{
        DiscreteLogVTMF, ElgamalCipher, VerifiableThresholdMaskingProtocol,
    };

    use ark_crypto_primitives::encryption::elgamal::Randomness;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::One;
    use ark_std::{test_rng, UniformRand, Zero};
    use rand::{seq::SliceRandom, thread_rng};
    use starknet_curve::{Affine, Fr, Projective};
    use std::iter::Iterator;

    fn generate_permutation(length: usize) -> Vec<usize> {
        let mut rng = thread_rng();
        let mut permutation: Vec<usize> = Vec::with_capacity(length);
        for i in 0..length {
            permutation.push(i);
        }
        permutation.shuffle(&mut rng);
        permutation
    }

    #[test]
    fn n_of_n_threshold_decryption_test() {
        let rng = &mut thread_rng();
        let rng1 = &mut thread_rng();
        let rng2 = &mut thread_rng();
        let rng3 = &mut thread_rng();

        // setup and key generation
        let parameters = DiscreteLogVTMF::setup(rng).unwrap();

        let (pk1, sk1) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng1).unwrap();
        let (pk2, sk2) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng2).unwrap();
        let (pk3, sk3) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng3).unwrap();

        let msg = Projective::rand(rng).into();
        let r0 = Randomness::rand(rng);
        let r1 = Randomness::rand(rng);
        let r2 = Randomness::rand(rng);
        let r3 = Randomness::rand(rng);

        let shared_key = pk1 + pk2 + pk3;

        let cipher =
            DiscreteLogVTMF::<Projective>::mask(&parameters, &shared_key, &msg, &r0).unwrap();

        // remasking once per player
        let remasked =
            DiscreteLogVTMF::<Projective>::remask(&parameters, &shared_key, &cipher, &r1).unwrap();
        let remasked =
            DiscreteLogVTMF::<Projective>::remask(&parameters, &shared_key, &remasked, &r2)
                .unwrap();
        let remasked =
            DiscreteLogVTMF::<Projective>::remask(&parameters, &shared_key, &remasked, &r3)
                .unwrap();

        // Players compute D = xi_C and publish
        let d1 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk1, &remasked).unwrap();
        let d2 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk2, &remasked).unwrap();
        let d3 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk3, &remasked).unwrap();

        let decrypted = DiscreteLogVTMF::<Projective>::unmask(&(d1 + d2 + d3), &remasked).unwrap();

        assert_eq!(decrypted, msg);
    }

    #[test]
    fn mask_shuffle_test() {
        let number_of_cards = 52;
        let rng = &mut test_rng();
        let rng1 = &mut thread_rng();

        let parameters = DiscreteLogVTMF::setup(rng).unwrap();

        let (master_pk, _) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng1).unwrap();

        let mut card_rng = thread_rng();
        let deck = (0..number_of_cards)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| {
                let one = Fr::one();
                DiscreteLogVTMF::<Projective>::mask(
                    &parameters,
                    &master_pk,
                    &Projective::rand(&mut card_rng).into(),
                    &Randomness(one),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let mut masking_rng = thread_rng();
        let masking_factors = (0..number_of_cards)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| {
                let masking_factor = Fr::rand(&mut masking_rng);
                Randomness(masking_factor)
            })
            .collect::<Vec<_>>();

        let permutation = generate_permutation(number_of_cards);

        let shuffled_deck = DiscreteLogVTMF::<Projective>::mask_shuffle(
            &parameters,
            &master_pk,
            &deck,
            &masking_factors,
            &permutation,
        )
        .unwrap();

        let sum_of_randomness: Option<Randomness<Projective>> = masking_factors
            .into_iter()
            .reduce(|a, b| Randomness(a.0 + b.0));
        let sum_of_deck: Option<ElgamalCipher<Projective>> = deck.into_iter().reduce(|a, b| a + b);
        let sum_of_shuffled: Option<ElgamalCipher<Projective>> =
            shuffled_deck.into_iter().reduce(|a, b| a + b);

        let global_masking = DiscreteLogVTMF::<Projective>::mask(
            &parameters,
            &master_pk,
            &Affine::zero(),
            &sum_of_randomness.unwrap(),
        )
        .unwrap();

        // E(I, sum_of_randomness) + sum_of_deck should be equal to sum_of_shuffled_deck
        let want = sum_of_deck.unwrap() + global_masking;
        assert_eq!(want, sum_of_shuffled.unwrap());
    }

    #[test]
    fn verified_masking_test() {
        let rng = &mut thread_rng();
        let rng1 = &mut thread_rng();

        // setup and key generation
        let parameters = DiscreteLogVTMF::setup(rng).unwrap();

        let (pk1, _) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng1).unwrap();

        let msg = Projective::rand(rng).into();

        let r0 = Randomness::rand(rng);

        let (cipher, proof) =
            DiscreteLogVTMF::<Projective>::verified_mask(&parameters, &pk1, &msg, &r0).unwrap();

        let negative_message = msg.mul(-Fr::one());
        let statement = (
            cipher.0,
            negative_message.add_mixed(&cipher.1).into_affine(),
        );

        let proof_parameters = Parameters {
            g: parameters.generator,
            h: pk1,
        };

        assert_eq!(proof.verify(&proof_parameters, &statement.into()), Ok(()));
    }

    #[test]
    fn verified_remasking_test() {
        let rng = &mut thread_rng();
        let rng1 = &mut thread_rng();

        // setup and key generation
        let parameters = DiscreteLogVTMF::setup(rng).unwrap();
        let (pk1, _) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng1).unwrap();

        // Message
        let msg = Projective::rand(rng).into();

        // Masked once
        let r0 = Randomness::rand(rng);
        let cipher = DiscreteLogVTMF::<Projective>::mask(&parameters, &pk1, &msg, &r0).unwrap();

        // Remasking
        let (remasked, proof) =
            DiscreteLogVTMF::<Projective>::verified_remask(&parameters, &pk1, &cipher, &r0)
                .unwrap();

        // Compute statement on verifier side
        let neg_one = -Fr::one();
        // let negative_cipher = DiscreteLogVTMF::<Projective>::mul(&cipher, &neg_one).unwrap();
        let negative_cipher = cipher * neg_one;
        let statement = remasked + negative_cipher;

        // Compute parameters on verifier side
        let proof_parameters = Parameters {
            g: parameters.generator,
            h: pk1,
        };

        // verify
        assert_eq!(proof.verify(&proof_parameters, &statement), Ok(()));
    }
}
