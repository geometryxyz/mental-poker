use crate::{fq::Fq, fr::Fr};
use ark_ec::{
    models::{ModelParameters, SWModelParameters},
    short_weierstrass_jacobian::{GroupAffine, GroupProjective},
};
use ark_ff::field_new;

#[cfg(test)]
mod tests;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct StarkwareParameters;

impl ModelParameters for StarkwareParameters {
    type BaseField = Fq;
    type ScalarField = Fr;
}

pub type Affine = GroupAffine<StarkwareParameters>;
pub type Projective = GroupProjective<StarkwareParameters>;

impl SWModelParameters for StarkwareParameters {
    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[1];

    /// COFACTOR_INV = 1
    const COFACTOR_INV: Fr = field_new!(Fr, "1");

    /// COEFF_A = 1
    const COEFF_A: Fq = field_new!(Fq, "1");

    /// COEFF_B = 3141592653589793238462643383279502884197169399375105820974944592307816406665
    const COEFF_B: Fq = field_new!(
        Fq,
        "3141592653589793238462643383279502884197169399375105820974944592307816406665"
    );

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (G_GENERATOR_X, G_GENERATOR_Y);
}

/// G_GENERATOR_X = 874739451078007766457464989774322083649278607533249481151382481072868806602
pub const G_GENERATOR_X: Fq = field_new!(
    Fq,
    "874739451078007766457464989774322083649278607533249481151382481072868806602"
);

/// G_GENERATOR_Y = 152666792071518830868575557812948353041420400780739481342941381225525861407
pub const G_GENERATOR_Y: Fq = field_new!(
    Fq,
    "152666792071518830868575557812948353041420400780739481342941381225525861407"
);
