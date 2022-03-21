#[cfg(test)]

mod test {

    use crate::homomorphic_encryption::{el_gamal, HomomorphicEncryptionScheme};
    use crate::utils::rand::sample_vector;
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use crate::zkp::{arguments::shuffle, ArgumentOfKnowledge};

    use crate::utils::permutation::Permutation;
    use ark_ff::Zero;
    use ark_std::{rand::thread_rng, UniformRand};
    use starknet_curve;
    use std::iter::Iterator;

    // Choose ellitptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Type aliases for concrete instances using the chosen EC.
    type Enc = el_gamal::ElGamal<Curve>;
    type Comm = pedersen::PedersenCommitment<Curve>;
    type Plaintext = el_gamal::Plaintext<Curve>;
    type Generator = el_gamal::Generator<Curve>;
    type Ciphertext = el_gamal::Ciphertext<Curve>;
    type Witness<'a> = shuffle::Witness<'a, Scalar>;
    type Statement<'a> = shuffle::Statement<'a, Scalar, Enc>;
    type ShuffleArgument<'a> = shuffle::ShuffleArgument<'a, Scalar, Enc, Comm>;
    type Parameters<'a> = shuffle::Parameters<'a, Scalar, Enc, Comm>;

    #[test]
    fn test_shuffle_argument() {
        let m = 4;
        let n = 13;
        let number_of_ciphers = n * m;

        let rng = &mut thread_rng();

        let encrypt_parameters = Enc::setup(rng).unwrap();
        let (pk, _) = Enc::keygen(&encrypt_parameters, rng).unwrap();

        let commit_key = Comm::setup(rng, n);

        let generator = Generator::rand(rng);

        let ciphers: Vec<Ciphertext> = sample_vector(rng, number_of_ciphers);
        let masking_factors: Vec<Scalar> = sample_vector(rng, number_of_ciphers);

        let permutation = Permutation::new(rng, number_of_ciphers);

        let permuted_ciphers = permutation.permute_array(&ciphers);

        let shuffled_deck = permuted_ciphers
            .iter()
            .zip(masking_factors.iter())
            .map(|(&cipher, masking_factor)| {
                let zero_cipher = Plaintext::zero();
                let masking_cipher =
                    Enc::encrypt(&encrypt_parameters, &pk, &zero_cipher, masking_factor).unwrap();

                cipher + masking_cipher
            })
            .collect::<Vec<_>>();

        let parameters = Parameters::new(&encrypt_parameters, &pk, &commit_key, &generator);
        let statement = Statement::new(&ciphers, &shuffled_deck, m, n);
        let witness = Witness::new(&permutation, &masking_factors);

        let valid_proof = ShuffleArgument::prove(rng, &parameters, &statement, &witness).unwrap();

        assert_eq!(
            Ok(()),
            ShuffleArgument::verify(&parameters, &statement, &valid_proof)
        );

        let new_permutation = Permutation::new(rng, number_of_ciphers);
        let bad_witness = Witness::new(&new_permutation, &masking_factors);

        let invalid_proof =
            ShuffleArgument::prove(rng, &parameters, &statement, &bad_witness).unwrap();
        assert_ne!(
            Ok(()),
            ShuffleArgument::verify(&parameters, &statement, &invalid_proof)
        );
    }
}
