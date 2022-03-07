use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_ff::{PrimeField, Zero};
use rand::Rng;
use std::marker::PhantomData;
use ark_std::UniformRand;
use verifiable_threshold_masking_protocol::discrete_log_vtmp::{ElgamalCipher};
use ark_ec::msm::VariableBaseMSM;
use super::error::Error;


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

pub trait DotProduct<C:ProjectiveCurve> {
    type Scalar;
    type Point;
    type Ciphertext;

    fn scalars_by_ciphers(
        scalars: &Vec<Self::Scalar>,
        ciphers: &Vec<Self::Ciphertext>)
        -> Result<Self::Ciphertext, Error>;

    fn scalars_by_points(
        scalars: &Vec<Self::Scalar>,
        points: &Vec<Self::Point>)
        -> Result<Self::Point, Error>;

    fn scalars_by_scalars(
        scalars_a: &Vec<Self::Scalar>,
        scalar_b: &Vec<Self::Scalar>)
        -> Result<Self::Scalar, Error>;
}

pub struct DotProductCalculator<C: ProjectiveCurve> {
    _curve: PhantomData<C>
}

impl<C: ProjectiveCurve> DotProduct<C> for DotProductCalculator<C> {
    type Scalar = C::ScalarField;
    type Point = C;
    type Ciphertext = ElgamalCipher<C>;

    fn scalars_by_ciphers(
        scalars: &Vec<Self::Scalar>,
        ciphers: &Vec<Self::Ciphertext>)
        -> Result<Self::Ciphertext, Error> {
        
        if ciphers.len() != scalars.len() {
            return Err(Error::DotProductLenError)
        }
    
        let dot_product: Self::Ciphertext = ciphers.iter().zip(scalars.iter()).map(|(cipher, scalar)| *cipher * *scalar).sum();
    
        Ok(dot_product)
    }


    fn scalars_by_points(
        scalars: &Vec<Self::Scalar>,
        points: &Vec<Self::Point>)
        -> Result<Self::Point, Error> {
        
        if points.len() != scalars.len() {
            return Err(Error::DotProductLenError)
        }
    
        let dot_product: Self::Point = points.iter().zip(scalars.iter()).map(|(&point, scalar)| point.mul(scalar.into_repr())).sum();
    
        Ok(dot_product)
    }
    
    fn scalars_by_scalars(
        scalars_a: &Vec<Self::Scalar>,
        scalars_b: &Vec<Self::Scalar>)
        -> Result<Self::Scalar, Error> {
        
        if scalars_a.len() != scalars_b.len() {
            return Err(Error::DotProductLenError)
        }
    
        let dot_product: Self::Scalar = scalars_a.iter().zip(scalars_b.iter()).map(|(s_a, s_b)| *s_a * *s_b).sum();
    
        Ok(dot_product)
    }
}

pub trait HadamardProduct<C:ProjectiveCurve> {
    type Scalar;

    fn scalars_by_scalars(
        scalars_a: &Vec<Self::Scalar>,
        scalars_b: &Vec<Self::Scalar>)
        -> Result<Vec<Self::Scalar>, Error>;
}

pub struct HadamardProductCalculator<C: ProjectiveCurve> {
    _curve: PhantomData<C>
}

impl<C: ProjectiveCurve> HadamardProduct<C> for HadamardProductCalculator<C> {
    type Scalar = C::ScalarField;

    fn scalars_by_scalars(
        scalars_a: &Vec<Self::Scalar>,
        scalars_b: &Vec<Self::Scalar>)
        -> Result<Vec<Self::Scalar>, Error> {
        
        if scalars_a.len() != scalars_b.len() {
            return Err(Error::HadamardProductLenError)
        }
    
        let hadamard_product: Vec<Self::Scalar> = scalars_a.iter().zip(scalars_b.iter()).map(|(&s_a, &s_b)| s_a * s_b).collect();
    
        Ok(hadamard_product)
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
