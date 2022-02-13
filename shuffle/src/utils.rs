use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;

use ark_ec::msm::VariableBaseMSM;

pub fn commit<C: ProjectiveCurve>(bases: &Vec<C::Affine>, x: &Vec<C::ScalarField>, r: C::ScalarField) -> C {
    let scalars = [x.as_slice(), &[r]].concat().iter().map(|x| x.into_repr()).collect::<Vec<_>>();
    VariableBaseMSM::multi_scalar_mul(&bases[..], &scalars)
}

#[cfg(test)]
mod test {
    use starknet_curve::{Projective};
    use starknet_curve::{Fr};
    use super::commit;
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
        let _cmt :Projective = commit(&bases, &x, a3);
    }
}