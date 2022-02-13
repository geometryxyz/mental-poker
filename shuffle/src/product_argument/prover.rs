use ark_ec::ProjectiveCurve;
use ark_ff::{Zero, One};

use ark_std::UniformRand;
use std::iter;
use merlin::Transcript;

use crate::utils::commit;
use crate::product_argument::proof::Proof;
use crate::transcript::TranscriptProtocol;

use std::marker::PhantomData;

pub struct Prover<C, const SIZE: usize> 
where 
    C: ProjectiveCurve
{
    phantom: PhantomData<C>
}

impl<C, const SIZE: usize> Prover<C, SIZE> 
where   
    C: ProjectiveCurve
{
    pub fn create_proof(commit_key: &Vec<C::Affine> ,transcript: &mut Transcript, a: Vec<C::ScalarField>) -> Proof<C, SIZE> {
        let mut rng = ark_std::rand::thread_rng();

        let r_a = C::ScalarField::rand(&mut rng);
        let a_commit = commit::<C>(&commit_key, &a, r_a);
        transcript.append(b"a_commit", &a_commit);

        // generate vector b
        let bs: Vec<C::ScalarField> = iter::once(a[0])
        .chain(a.iter().skip(1).scan(a[0], |st, elem| {
            *st *= elem;
            Some(*st)
        }))
        .collect();

        // sample d1..dn & delta_2..delta_n-1
        let mut ds = vec![C::ScalarField::zero(); SIZE];
        let mut deltas = vec![C::ScalarField::zero(); SIZE];
        for i in 0..SIZE {
            ds[i] = C::ScalarField::rand(&mut rng);
            deltas[i] = C::ScalarField::rand(&mut rng);
        }

        deltas[0] = ds[0];
        deltas[SIZE - 1] = C::ScalarField::zero();

        // // sample rd
        let r_d = C::ScalarField::rand(&mut rng);

        // sample s1, sx
        let s_1 = C::ScalarField::rand(&mut rng);
        let s_x = C::ScalarField::rand(&mut rng);

        let d_commit = commit::<C>(&commit_key, &ds, r_d);

        let minus_one = -C::ScalarField::one();
        let delta_ds = deltas.split_last().unwrap().1.iter().zip(ds.iter().skip(1)).map(|(delta, d)| {
            minus_one * delta * d
        }).collect::<Vec<_>>();

        let delta_ds_commit = commit::<C>(&commit_key, &delta_ds, s_1);

        let mut diffs = vec![C::ScalarField::zero(); SIZE - 1];

        //TODO implement this with windows&iters
        for i in 0..SIZE-1 {
            diffs[i] = deltas[i + 1] - a[i + 1]*deltas[i] - bs[i]*ds[i + 1]
        }

        let diff_commit = commit::<C>(&commit_key, &diffs, s_x);

        transcript.append(b"d_commit", &d_commit);
        transcript.append(b"delta_ds_commit", &delta_ds_commit);
        transcript.append(b"diff_commit", &diff_commit);

        let x = transcript.challenge_scalar(b"x");

        let a_blinded = Self::blind(&a, &ds, x);
        let r_blinded = x * r_a + r_d;

        let b_blinded = Self::blind(&bs, &deltas, x);
        let s_blinded = x * s_x + s_1;

        Proof {
            a_commit,
            d_commit,
            delta_ds_commit,
            diff_commit,
            a_blinded,
            b_blinded,
            r_blinded,
            s_blinded,
        }
    }

    fn blind(x: &Vec<C::ScalarField>, blinders: &Vec<C::ScalarField>, challenge: C::ScalarField) -> Vec<C::ScalarField> {
        let blinded = x.iter().zip(blinders.iter()).map(|(x, b)| {
            challenge*x + b
        }).collect::<Vec<C::ScalarField>>();

        blinded
    }
}