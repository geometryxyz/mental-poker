pub mod commitment_key;

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::{
        commitment::{
            pedersen::{Commitment, Randomness}, CommitmentScheme,
        },
        crh::pedersen,
    };

    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_serialize::{CanonicalSerialize};

    use starknet_curve::{Projective, Fr};
    use ark_std::{test_rng, UniformRand};



    #[test]
    fn pedersen_commitment() {
        const SERIALIZED_SIZE: usize = 256;

        #[derive(Clone, PartialEq, Eq, Hash)]
        pub(super) struct Window;

        impl pedersen::Window for Window {
            const WINDOW_SIZE: usize = 256;
            const NUM_WINDOWS: usize = 10;
        }

        let rng = &mut test_rng();
        let x = Fr::rand(rng);

        let a = vec![x; 10];

        let a_serialized = a.iter().map(|x| {
            let mut serialized = vec![0; 32];
            x.serialize(&mut serialized[..]).unwrap();
            serialized
        }).collect::<Vec<_>>();

        let a_serialized = a_serialized.into_iter().flatten().collect::<Vec<u8>>();

        let y = Fr::rand(rng);
        let d = vec![y; 10];

        let d_serialized = d.iter().map(|x| {
            let mut serialized = vec![0; 32];
            x.serialize(&mut serialized[..]).unwrap();
            serialized
        }).collect::<Vec<_>>();

        let d_serialized = d_serialized.into_iter().flatten().collect::<Vec<u8>>();

        let r = Fr::rand(rng);
        let randomness = Randomness(r);

        let parameters = Commitment::<Projective, Window>::setup(rng).unwrap();

        println!("{}", parameters.generators.len());

        let a_commit =
            Commitment::<Projective, Window>::commit(&parameters, &a_serialized, &randomness).unwrap();

        let d_commit =
            Commitment::<Projective, Window>::commit(&parameters, &d_serialized, &randomness).unwrap();


        let challenge = Fr::rand(rng);

        let a_prime = a.into_iter().zip(d.into_iter()).map(|(a, d)| {
            challenge*a + d
        }).collect::<Vec<Fr>>();

        let a_prime_serialized = a_prime.iter().map(|x| {
            let mut serialized = vec![0; 32];
            x.serialize(&mut serialized[..]).unwrap();
            serialized
        }).collect::<Vec<_>>();

        let a_prime_serialized = a_prime_serialized.into_iter().flatten().collect::<Vec<u8>>();

        let r_prime = challenge*r + r;

        let a_prime_commit =
            Commitment::<Projective, Window>::commit(&parameters, &a_prime_serialized, &Randomness(r_prime)).unwrap();

        println!("{:?}", a_prime_commit);

        let ca_x_cd = a_commit.mul(challenge).into_affine() + d_commit;

        assert_eq!(ca_x_cd, a_prime_commit);

    }
}

/*

CommitmentKey
  window
  public_randomnes
  parameters
  



Proof



 - commit
 - blinding

*/
