pub mod pedersen;
use ark_ec::ProjectiveCurve;

pub trait HomomorphicCommitment<C: ProjectiveCurve> {
    fn commit_scalar(g: C::Affine, h: C::Affine, x: C::ScalarField, r: C::ScalarField) -> C;

    fn commit_vector(commit_key: &Vec<C::Affine>, x: &Vec<C::ScalarField>, r: C::ScalarField) -> C;
}
