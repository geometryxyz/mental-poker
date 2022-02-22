use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_ff::{PrimeField, Zero};
use rand::Rng;
use std::marker::PhantomData;
use ark_std::UniformRand;

use ark_ec::msm::VariableBaseMSM;

// pub fn commit<C: ProjectiveCurve>(bases: &Vec<C::Affine>, x: &Vec<C::ScalarField>, r: C::ScalarField) -> C {
//     let scalars = [x.as_slice(), &[r]].concat().iter().map(|x| x.into_repr()).collect::<Vec<_>>();
//     VariableBaseMSM::multi_scalar_mul(&bases[..], &scalars)
// }

pub trait HomomorphicCommitment<C: ProjectiveCurve> {
    fn commit_scalar(g: C::Affine, h: C::Affine, x: C::ScalarField, r: C::ScalarField) -> C;

    fn commit_vector(commit_key: &Vec<C::Affine>, x: &Vec<C::ScalarField>, r: C::ScalarField) -> C;
}

pub struct PedersenCommitment<C: ProjectiveCurve> {
    _curve: PhantomData<C>
}

impl<C: ProjectiveCurve> HomomorphicCommitment<C> for PedersenCommitment<C> {
    fn commit_scalar(g: C::Affine, h: C::Affine, x: C::ScalarField, r: C::ScalarField) -> C {
        g.mul(x) + h.mul(r)
    }

    fn commit_vector(commit_key: &Vec<C::Affine>, x: &Vec<C::ScalarField>, r: C::ScalarField) -> C {
        let scalars = [x.as_slice(), &[r]].concat().iter().map(|x| x.into_repr()).collect::<Vec<_>>();
        VariableBaseMSM::multi_scalar_mul(&commit_key[..], &scalars)
    }
}

pub trait RandomSampler<C: ProjectiveCurve> {
    type Output;

    fn default(length: usize) -> Vec<Self::Output> ;

    fn sample_element<R: Rng>(seed: &mut R) -> Self::Output;

    fn sample_vector<R: Rng>(seed: &mut R, length: usize) -> Vec<Self::Output>;
}

pub struct PointSampler<C: ProjectiveCurve> {
    _curve: PhantomData<C>
}

pub struct ScalarSampler<C: ProjectiveCurve> {
    _curve: PhantomData<C>
}

impl<C: ProjectiveCurve> RandomSampler<C> for ScalarSampler<C> {
    type Output = C::ScalarField;

    fn default(length: usize) -> Vec<Self::Output> {
        let default_scalars = (0..length).collect::<Vec<usize>>().iter().map(|_| {
            C::ScalarField::zero()
        }).collect::<Vec<_>>();

        default_scalars
    }

    fn sample_element<R: Rng>(seed: &mut R) -> Self::Output {
        C::ScalarField::rand(seed)
    }
    
    fn sample_vector<R: Rng>(seed: &mut R, length: usize) -> Vec<Self::Output> {
        let random_scalars = (0..length).collect::<Vec<usize>>().iter().map(|_| {
            C::ScalarField::rand(seed)
        }).collect::<Vec<_>>();

        random_scalars
    }
}


impl<C: ProjectiveCurve> RandomSampler<C> for PointSampler<C> {
    type Output = C;

    fn default(length: usize) -> Vec<Self::Output> {
        let default_points = (0..length).collect::<Vec<usize>>().iter().map(|_| {
            C::zero()
        }).collect::<Vec<_>>();

        default_points
    }

    fn sample_element<R: Rng>(seed: &mut R) -> Self::Output {
        C::rand(seed)
    }
    
    fn sample_vector<R: Rng>(seed: &mut R, length: usize) -> Vec<Self::Output> {
        let random_points = (0..length).collect::<Vec<usize>>().iter().map(|_i| {
            C::rand(seed)
        }).collect::<Vec<C>>();

        random_points
    }
}


#[cfg(test)]
mod test {
    use starknet_curve::{Projective};
    use starknet_curve::{Fr};
    use super::{HomomorphicCommitment, PedersenCommitment};
    use ark_std::{test_rng, UniformRand};
    use ark_ec::ProjectiveCurve;

    #[test]
    fn test_commit() {
        let rng = &mut test_rng();
        let a1 = Fr::rand(rng);
        let a2 = Fr::rand(rng);
        let a3 = Fr::rand(rng);

        let b1 = Projective::rand(rng);
        let b2 = Projective::rand(rng);
        let b3 = Projective::rand(rng);

        let bases = vec![b1.into_affine(), b2.into_affine(), b3.into_affine()];
        let x = vec![a1, a2];
        let _cmt :Projective = PedersenCommitment::<Projective>::commit_vector(&bases, &x, a3);
    }
}