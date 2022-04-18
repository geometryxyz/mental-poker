use rand::{seq::SliceRandom, Rng};

/// Represent a permutation pi as a vector such that for all indices i, vec(i) = pi(i)
pub struct Permutation {
    pub mapping: Vec<usize>,
    pub size: usize,
}

impl Permutation {
    pub fn new<R: Rng>(rng: &mut R, size: usize) -> Self {
        let mut mapping: Vec<usize> = Vec::with_capacity(size);
        for i in 0..size {
            mapping.push(i);
        }
        mapping.shuffle(rng);
        Self { mapping, size }
    }

    pub fn from(permutation_vec: &Vec<usize>) -> Self {
        Self {
            mapping: permutation_vec[..].to_vec(),
            size: permutation_vec.len(),
        }
    }

    pub fn identity(size: usize) -> Self {
        Self {
            mapping: (0..size).collect(),
            size: size,
        }
    }

    pub fn permute_array<T: Copy>(&self, input_vector: &Vec<T>) -> Vec<T> {
        self.mapping
            .iter()
            .map(|&pi_i| input_vector[pi_i])
            .collect::<Vec<T>>()
    }
}
