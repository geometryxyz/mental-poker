use ark_std::UniformRand;
use rand::Rng;
use std::marker::PhantomData;

pub struct RandomSampler<T: UniformRand> {
    _type: PhantomData<T>,
}

impl<T: UniformRand> RandomSampler<T> {
    pub fn sample_item<R: Rng>(seed: &mut R) -> T {
        T::rand(seed)
    }

    pub fn sample_vector<R: Rng>(seed: &mut R, length: usize) -> Vec<T> {
        (0..length)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| T::rand(seed))
            .collect::<Vec<_>>()
    }
}
