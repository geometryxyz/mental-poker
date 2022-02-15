#[cfg(test)]
mod test {
    use crate::discrete_log_vtmp::{DiscreteLogVTMF, VerifiableThresholdMaskingProtocol, HomomorphicScheme};
    use ark_crypto_primitives::encryption::elgamal::{Randomness};
    use starknet_curve::{Projective, Fr};
    use ark_std::{test_rng, UniformRand};
    use ark_ec::{ProjectiveCurve, AffineCurve};
    use ark_ff::{One};
    use rand::{thread_rng, seq::SliceRandom};
    use std::iter::Iterator;
    use ark_crypto_primitives::encryption::{AsymmetricEncryptionScheme, elgamal::*};


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
    fn random_test() {
        let rng = &mut test_rng();
        let rng1 = &mut thread_rng();
        let rng2 = &mut thread_rng();
        let rng3 = &mut thread_rng();


        // setup and key generation
        let parameters = DiscreteLogVTMF::setup(rng).unwrap();

        let (pk1, sk1) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng1).unwrap();
        let (pk2, sk2) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng2).unwrap();
        let (pk3, sk3) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng3).unwrap();

        let msg = Projective::rand(rng).into();
        let r = Randomness::rand(rng);

        let shared_key = pk1 + pk2 + pk3;

        let cipher = DiscreteLogVTMF::<Projective>::mask(&parameters, &shared_key, &msg, &r).unwrap();

        let d1 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk1, &cipher).unwrap();
        let d2 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk2, &cipher).unwrap();
        let d3 = DiscreteLogVTMF::<Projective>::compute_decryption_key(&sk3, &cipher).unwrap();

        let master_decryption_key = d1 + d2 + d3;

        let decrypted = DiscreteLogVTMF::<Projective>::unmask(&master_decryption_key, &cipher).unwrap();

        assert_eq!(decrypted, msg);
    }


    // #[test]
    // fn mask_shuffle_test() {
    //     let number_of_cards = 52;
    //     let rng = &mut test_rng();
    //     let rng1 = &mut thread_rng();

    //     let parameters = DiscreteLogVTMF::setup(rng).unwrap();

    //     let (master_pk, _) = DiscreteLogVTMF::<Projective>::keygen(&parameters, rng1).unwrap();

    //     let mut card_rng = thread_rng();
    //     let deck = (0..number_of_cards).collect::<Vec<usize>>().iter().map(|x| {
    //         let one = Fr::one();
    //         DiscreteLogVTMF::<Projective>::mask(&parameters, &master_pk, &Projective::rand(&mut card_rng).into(), &Randomness(one)).unwrap()
    //     }).collect::<Vec<_>>();

    //     let mut masking_rng = thread_rng();
    //     let masking_factors = (0..number_of_cards).collect::<Vec<usize>>().iter().map(|x| {
    //         let masking_factor = Fr::rand(&mut masking_rng);
    //         Randomness(masking_factor)
    //     }).collect::<Vec<_>>();

    //     let permutation = generate_permutation(number_of_cards);

    //     let shuffled_deck = DiscreteLogVTMF::<Projective>::mask_shuffle(&parameters, &master_pk, &deck, &masking_factors, &permutation);

    //     let sum = ElGamal::add(deck[0], deck[1]);

    //     let sum_of_randomness: Option<Randomness<Projective>> = masking_factors.into_iter().reduce(|a, b| { Randomness(a.0 + b.0) });
    //     let sum_of_deck: Option<DiscreteLogVTMF::<Projective>::Ciphertext> = deck.into_iter().reduce(|a, b| { ElGamal::<Projective>::add(a, b) });
    //     // let sum_of_shuffled: Option<DiscreteLogVTMF::<Projective>::Ciphertext> = deck.into_iter().reduce(|a, b| { DiscreteLogVTMF::<Projective>::add(a, b) });

        
    // }
}