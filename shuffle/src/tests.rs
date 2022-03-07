#[cfg(test)]

mod test {
    use ark_ec::{ProjectiveCurve};
    use ark_ff::{One, UniformRand};
    use starknet_curve::{Fr};
    use ark_std::rand::{thread_rng};
    use rand::Rng;
    use verifiable_threshold_masking_protocol::discrete_log_vtmp::{VerifiableThresholdMaskingProtocol, DiscreteLogVTMF};
    use crate::{Permutation, prover::Prover, Parameters, Statement, Witness};
    use ark_crypto_primitives::{encryption::elgamal::{Randomness, ElGamal}};

    fn generate_commit_key<R: Rng, C: ProjectiveCurve>(public_randomess: &mut R, len: &usize) -> Vec<C::Affine> {
        let mut commit_key = Vec::with_capacity(len + 1);
        let mut base = C::rand(public_randomess);
        for _ in 0..len + 1 {
            commit_key.push(base.into_affine());
            base.double_in_place();
        }
        commit_key
    }

    #[test] 
    fn test_shuffle_argument() {
        let m = 4;
        let n = 13;
        let number_of_cards = n * m;

        let rng = &mut thread_rng();

        let commit_key = generate_commit_key::<_, starknet_curve::Projective>(rng, &n);

        let elgamal_parameters = DiscreteLogVTMF::setup(rng).unwrap();
        let (pk, _) = DiscreteLogVTMF::<starknet_curve::Projective>::keygen(&elgamal_parameters, rng).unwrap();

        let mut card_rng = thread_rng();
        let deck = (0..number_of_cards).collect::<Vec<usize>>().iter().map(|_| {
            let one = Fr::one();
            DiscreteLogVTMF::<starknet_curve::Projective>::mask(
                &elgamal_parameters,
                &pk,
                &starknet_curve::Projective::rand(&mut card_rng).into(),
                &Randomness(one)
            ).unwrap()
        }).collect::<Vec<_>>();

        let mut masking_rng = thread_rng();
        let masking_factors = (0..number_of_cards).collect::<Vec<usize>>().iter().map(|_| {
            let masking_factor = Fr::rand(&mut masking_rng);
            Randomness(masking_factor)
        }).collect::<Vec<_>>();

        let masking_factors_raw = masking_factors.iter().map(|x| x.0).collect::<Vec<_>>();

        let permutation = Permutation::new(rng, number_of_cards);

        let shuffled_deck = DiscreteLogVTMF::<starknet_curve::Projective>::mask_shuffle(
            &elgamal_parameters, 
            &pk, 
            &deck, 
            &masking_factors, 
            &permutation.mapping
        ).unwrap();
        
        let parameters = Parameters::<starknet_curve::Projective>::new(&pk, &commit_key);
        let statement = Statement::<starknet_curve::Projective>::new(&deck, &shuffled_deck, m, n);
        let witness = Witness::<starknet_curve::Projective>::new(
            &permutation,
            &masking_factors_raw
        );

        let honest_prover = Prover::<starknet_curve::Projective, ElGamal<starknet_curve::Projective>>::new(&parameters, &statement, &witness);
        let valid_proof = honest_prover.prove(rng, &elgamal_parameters);
        assert_eq!(Ok(()), valid_proof.verify(&parameters, &statement, &elgamal_parameters));

        let new_permutation = Permutation::new(rng, number_of_cards);
        let bad_witness = Witness::<starknet_curve::Projective>::new(
            &new_permutation,
            &masking_factors_raw
        );

        let malicious_prover = Prover::<starknet_curve::Projective, ElGamal<starknet_curve::Projective>>::new(
            &parameters,
            &statement,
            &bad_witness
        );     
            
        let invalid_proof = malicious_prover.prove(rng, &elgamal_parameters);
        assert_ne!(Ok(()), invalid_proof.verify(&parameters, &statement, &elgamal_parameters));
    }
}