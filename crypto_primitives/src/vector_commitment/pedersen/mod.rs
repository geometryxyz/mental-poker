use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitment;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use rand::Rng;

mod test;

pub struct PedersenCommitment<C: ProjectiveCurve> {
    _curve: PhantomData<C>,
}

pub struct CommitKey<C: ProjectiveCurve> {
    g: Vec<C::Affine>,
    h: C::Affine,
}

impl<C: ProjectiveCurve> HomomorphicCommitment<C> for PedersenCommitment<C> {
    type CommitKey = CommitKey<C>;

    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> CommitKey<C> {
        let mut g = Vec::with_capacity(len);
        for _ in 0..len {
            g.push(C::rand(public_randomess).into_affine());
        }
        let h = C::rand(public_randomess).into_affine();
        CommitKey::<C> { g, h }
    }

    fn commit(
        commit_key: &CommitKey<C>,
        x: &Vec<C::ScalarField>,
        r: C::ScalarField,
    ) -> Result<C, CryptoError> {
        if x.len() > commit_key.g.len() {
            return Err(CryptoError::CommitmentLengthError(
                String::from("Pedersen"),
                x.len(),
                commit_key.g.len(),
            ));
        }

        let scalars = [&[r], x.as_slice()]
            .concat()
            .iter()
            .map(|x| x.into_repr())
            .collect::<Vec<_>>();

        let bases = [&[commit_key.h], &commit_key.g[..]].concat();

        Ok(VariableBaseMSM::multi_scalar_mul(&bases, &scalars))
    }
}
