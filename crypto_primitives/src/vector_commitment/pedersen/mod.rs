use crate::error::CryptoError;
use crate::utils::ops::{FromField, ToField};
use crate::vector_commitment::HomomorphicCommitmentScheme;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::marker::PhantomData;
use rand::Rng;

pub mod commitment_arithmetic;
// mod test;

pub struct PedersenCommitment<C: ProjectiveCurve> {
    _curve: PhantomData<C>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct CommitKey<C: ProjectiveCurve> {
    g: Vec<C::Affine>,
    h: C::Affine,
}

impl<C: ProjectiveCurve> CommitKey<C> {
    pub fn new(g: Vec<C::Affine>, h: C::Affine) -> Self {
        Self { g, h }
    }
}

#[derive(Clone, Copy, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<C: ProjectiveCurve>(pub C::Affine);

#[derive(Clone, Copy, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Scalar<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> ToField<C::ScalarField> for Scalar<C> {
    fn into_field(self) -> C::ScalarField {
        self.0
    }
}

impl<C: ProjectiveCurve> FromField<C::ScalarField> for Scalar<C> {
    fn from_field(x: C::ScalarField) -> Scalar<C> {
        Scalar::<C>(x)
    }
}

impl<C: ProjectiveCurve> HomomorphicCommitmentScheme<C::ScalarField> for PedersenCommitment<C> {
    type CommitKey = CommitKey<C>;
    type Scalar = Scalar<C>;
    type Commitment = Commitment<C>;

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
        x: &Vec<Self::Scalar>,
        r: Self::Scalar,
    ) -> Result<Self::Commitment, CryptoError> {
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
            .map(|x| x.into_scalarfield().into_repr())
            .collect::<Vec<_>>();

        let bases = [&[commit_key.h], &commit_key.g[..]].concat();

        Ok(Self::Commitment::from_projective(
            VariableBaseMSM::multi_scalar_mul(&bases, &scalars[..]),
        ))
    }
}

impl<C: ProjectiveCurve> Scalar<C> {
    pub fn into_scalarfield(self) -> C::ScalarField {
        self.0
    }

    pub fn from(x: C::ScalarField) -> Self {
        Self(x)
    }
}

impl<C: ProjectiveCurve> std::ops::Add<Scalar<C>> for Scalar<C> {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self {
        Self(self.0 + _rhs.0)
    }
}

impl<C: ProjectiveCurve> std::ops::Mul<Scalar<C>> for Scalar<C> {
    type Output = Self;

    fn mul(self, _rhs: Self) -> Self {
        Self(self.0 * _rhs.0)
    }
}
