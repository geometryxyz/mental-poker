use ark_ec::ProjectiveCurve;
use rand::Rng;


//TODO add public key
#[derive(Clone)]
pub struct PublicConfig<C, const SIZE: usize>
where 
    C: ProjectiveCurve
{
    pub commit_key: Vec<C::Affine>
}

impl<C, const SIZE: usize> PublicConfig<C, SIZE>
where 
    C: ProjectiveCurve
{
    pub fn new<R: Rng>(public_randomess: &mut R) -> Self {
        Self {
            commit_key: Self::generate_commit_key(public_randomess)
        }
    }
    fn generate_commit_key<R: Rng>(public_randomess: &mut R) -> Vec<C::Affine> {
        let mut commit_key = Vec::with_capacity(SIZE + 1);
        let mut base = C::rand(public_randomess);
        for _ in 0..SIZE + 1 {
            commit_key.push(base.into_affine());
            base.double_in_place();
        }
        commit_key
    }
}