#[cfg(test)]
mod test {
    use super::super::super::{el_gamal, HomomorphicEncryptionScheme};
    use crate::utils::rand::sample_vector;

    use ark_std::rand::thread_rng;
    use starknet_curve;
    use std::ops::Mul;

    // Define type aliases for succinctness
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;
    type ElGamal = el_gamal::ElGamal<Curve>;
    type Plaintext = el_gamal::Plaintext<Curve>;
    use ark_std::UniformRand;

    #[test]
    fn valid_encrypt_decrypt() {
        let rng = &mut thread_rng();
        let n = 50;

        let parameters = ElGamal::setup(rng).unwrap();
        let (pk, sk) = ElGamal::keygen(&parameters, rng).unwrap();

        let messages: Vec<Plaintext> = sample_vector(rng, n);
        let randoms: Vec<Scalar> = sample_vector(rng, n);

        let encrypted = messages
            .iter()
            .zip(randoms.iter())
            .map(|(m, r)| ElGamal::encrypt(&parameters, &pk, m, r).unwrap())
            .collect::<Vec<_>>();

        let decrypted = encrypted
            .iter()
            .map(|c| ElGamal::decrypt(&parameters, &sk, c).unwrap())
            .collect::<Vec<_>>();

        for (computed, expected) in decrypted.iter().zip(messages.iter()) {
            assert_eq!(computed, expected)
        }
    }
    #[test]
    fn failed_encrypt_decrypt() {
        let rng = &mut thread_rng();
        let n = 50;

        let parameters = ElGamal::setup(rng).unwrap();
        let (pk, _) = ElGamal::keygen(&parameters, rng).unwrap();

        let messages: Vec<Plaintext> = sample_vector(rng, n);
        let randoms: Vec<Scalar> = sample_vector(rng, n);

        let encrypted = messages
            .iter()
            .zip(randoms.iter())
            .map(|(m, r)| ElGamal::encrypt(&parameters, &pk, m, r).unwrap())
            .collect::<Vec<_>>();

        let wrong_sk = Scalar::rand(rng);

        let decrypted = encrypted
            .iter()
            .map(|c| ElGamal::decrypt(&parameters, &wrong_sk, c).unwrap())
            .collect::<Vec<_>>();

        for (computed, expected) in decrypted.iter().zip(messages.iter()) {
            assert_ne!(computed, expected)
        }
    }

    #[test]
    /// Verify that Dec(alpha * Enc(m1) + beta * Enc(m2)) = alpha * m1 + beta * m2
    fn homomorphic_property() {
        let rng = &mut thread_rng();

        let parameters = ElGamal::setup(rng).unwrap();
        let (pk, sk) = ElGamal::keygen(&parameters, rng).unwrap();

        let m1 = Plaintext::rand(rng);
        let r1 = Scalar::rand(rng);
        let c1 = ElGamal::encrypt(&parameters, &pk, &m1, &r1).unwrap();

        let m2 = Plaintext::rand(rng);
        let r2 = Scalar::rand(rng);
        let c2 = ElGamal::encrypt(&parameters, &pk, &m2, &r2).unwrap();

        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);

        let m3 = m1.mul(alpha) + m2.mul(beta);
        let c3 = c1.mul(alpha) + c2.mul(beta);

        let decrypted = ElGamal::decrypt(&parameters, &sk, &c3).unwrap();

        assert_eq!(m3, decrypted)
    }
}
