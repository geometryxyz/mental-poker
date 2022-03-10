use crate::vector_commitment::HomomorphicCommitment;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

pub struct PedersenCommitment<C: ProjectiveCurve> {
    _curve: PhantomData<C>,
}

impl<C: ProjectiveCurve> HomomorphicCommitment<C> for PedersenCommitment<C> {
    fn commit_scalar(g: C::Affine, h: C::Affine, x: C::ScalarField, r: C::ScalarField) -> C {
        g.mul(x) + h.mul(r)
    }

    fn commit_vector(commit_key: &Vec<C::Affine>, x: &Vec<C::ScalarField>, r: C::ScalarField) -> C {
        let scalars = [x.as_slice(), &[r]]
            .concat()
            .iter()
            .map(|x| x.into_repr())
            .collect::<Vec<_>>();
        VariableBaseMSM::multi_scalar_mul(&commit_key[..], &scalars)
    }
}
