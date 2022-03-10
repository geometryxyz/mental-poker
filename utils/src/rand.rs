use ark_ec::ProjectiveCurve;
use ark_ff::Zero;
use ark_std::UniformRand;
use rand::Rng;
use std::marker::PhantomData;

pub trait RandomSampler<C: ProjectiveCurve> {
    type Output;

    fn default(length: usize) -> Vec<Self::Output>;

    fn sample_element<R: Rng>(seed: &mut R) -> Self::Output;

    fn sample_vector<R: Rng>(seed: &mut R, length: usize) -> Vec<Self::Output>;
}

pub struct PointSampler<C: ProjectiveCurve> {
    _curve: PhantomData<C>,
}

pub struct ScalarSampler<C: ProjectiveCurve> {
    _curve: PhantomData<C>,
}

impl<C: ProjectiveCurve> RandomSampler<C> for ScalarSampler<C> {
    type Output = C::ScalarField;

    fn default(length: usize) -> Vec<Self::Output> {
        let default_scalars = (0..length)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| C::ScalarField::zero())
            .collect::<Vec<_>>();

        default_scalars
    }

    fn sample_element<R: Rng>(seed: &mut R) -> Self::Output {
        C::ScalarField::rand(seed)
    }

    fn sample_vector<R: Rng>(seed: &mut R, length: usize) -> Vec<Self::Output> {
        let random_scalars = (0..length)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| C::ScalarField::rand(seed))
            .collect::<Vec<_>>();

        random_scalars
    }
}

impl<C: ProjectiveCurve> RandomSampler<C> for PointSampler<C> {
    type Output = C;

    fn default(length: usize) -> Vec<Self::Output> {
        let default_points = (0..length)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| C::zero())
            .collect::<Vec<_>>();

        default_points
    }

    fn sample_element<R: Rng>(seed: &mut R) -> Self::Output {
        C::rand(seed)
    }

    fn sample_vector<R: Rng>(seed: &mut R, length: usize) -> Vec<Self::Output> {
        let random_points = (0..length)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_i| C::rand(seed))
            .collect::<Vec<C>>();

        random_points
    }
}
