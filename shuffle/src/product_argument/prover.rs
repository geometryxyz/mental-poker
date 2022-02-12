use ark_crypto_primitives::{
    commitment::{
        pedersen::{Commitment, Randomness, Parameters}, CommitmentScheme,
    },
};

use ark_ec::ProjectiveCurve;
use ark_serialize::{CanonicalSerialize};
use ark_ff::{Zero, One};

use ark_std::{test_rng, UniformRand};
use std::iter;
use merlin::Transcript;

use crate::config::{PublicConfig, ProductArgumentWindow};
use crate::product_argument::proof::Proof;
use crate::product_argument::transcript::TranscriptProtocol;

pub struct Prover<C, const SIZE: usize> 
where 
    C: ProjectiveCurve
{
    commit_parameters: Parameters<C>,
    transcript: Transcript,
    a: [C::ScalarField; SIZE],
    b: C::ScalarField
}

impl<C, const SIZE: usize> Prover<C, SIZE> 
where   
    C: ProjectiveCurve
{

    pub fn new(config: PublicConfig<C>, label: &'static [u8], a: [C::ScalarField; SIZE], b: C::ScalarField) -> Self {
        Self {
            commit_parameters: config.parameters,
            transcript: Transcript::new(label),
            a,
            b
        }
    }

    pub fn create_proof(&self) -> Proof<C, SIZE> {
        let rng = &mut test_rng();
        let a = Vec::from(self.a);
        let r = Randomness(C::ScalarField::rand(rng));
        let a_commit = self.commit(&a, &r);

        let mut transcript = self.transcript.clone();

        transcript.append(b"a_commit", &a_commit);
        transcript.append(b"b", &self.b);

        // generate vector b
        let bs: Vec<C::ScalarField> = iter::once(self.a[0])
        .chain(self.a.iter().skip(1).scan(self.a[0], |st, elem| {
            *st *= elem;
            Some(*st)
        }))
        .collect();


        // sample d1..dn & delta_2..delta_n-1
        let mut ds = vec![C::ScalarField::zero(); SIZE];
        let mut deltas = vec![C::ScalarField::zero(); SIZE];
        for i in 0..SIZE {
            ds[i] = C::ScalarField::rand(rng);
            deltas[i] = C::ScalarField::rand(rng);
        }

        deltas[0] = ds[0];
        deltas[SIZE - 1] = C::ScalarField::zero();

        // sample rd
        let rd = Randomness(C::ScalarField::rand(rng));

        // sample s1, sx
        let s1 = Randomness(C::ScalarField::rand(rng));
        let sx = Randomness(C::ScalarField::rand(rng));

        let d_commit = self.commit(&ds, &rd);

        let one = C::ScalarField::one();
        let minus_one = -one;
        let delta_ds = deltas.split_last().unwrap().1.iter().zip(ds.iter().skip(1)).map(|(delta, d)| {
            minus_one * delta * d
        }).collect::<Vec<_>>();

        let delta_ds_commit = self.commit(&delta_ds, &s1);

        let mut diffs = vec![C::ScalarField::zero(); SIZE - 1];

        for i in 0..SIZE-1 {
            diffs[i] = deltas[i + 1] - a[i + 1]*deltas[i] - bs[i]*ds[i + 1]
        }

        let diff_commit = self.commit(&diffs, &sx);

        transcript.append(b"d_commit", &d_commit);
        transcript.append(b"delta_ds_commit", &delta_ds_commit);
        transcript.append(b"diff_commit", &diff_commit);

        let x = transcript.challenge_scalar(b"x");

        let a_blinded = self.blind(&a, &ds, x);
        let r_blinded = Randomness::<C>(x * r.0 + rd.0);

        let b_blinded = self.blind(&bs, &deltas, x);
        let s_blinded = Randomness::<C>(x * sx.0 + s1.0);

        Proof {
            d_commit,
            a_commit,
            delta_ds_commit,
            diff_commit,
            a_blinded,
            b_blinded,
            r_blinded: r_blinded.0,
            s_blinded: s_blinded.0,
        }
    }

    fn commit(&self, x: &Vec<C::ScalarField>, r: &Randomness<C>) -> C::Affine {
        let serialized = x.iter().map(|x| {
            let mut serialized = vec![0; 32];
            x.serialize(&mut serialized[..]).unwrap();
            serialized
        }).collect::<Vec<_>>();

        let serialized = serialized.into_iter().flatten().collect::<Vec<u8>>();

        let commitment = 
            Commitment::<C, ProductArgumentWindow>::commit(&self.commit_parameters, &serialized, r).unwrap();

        commitment
    }

    fn blind(&self, x: &Vec<C::ScalarField>, blinders: &Vec<C::ScalarField>, challenge: C::ScalarField) -> Vec<C::ScalarField> {
        let blinded = x.iter().zip(blinders.iter()).map(|(x, b)| {
            challenge*x + b
        }).collect::<Vec<C::ScalarField>>();

        blinded
    }
}