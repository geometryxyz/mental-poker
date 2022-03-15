use super::{MaskedCard, ProofMasking};
use crate::Verifiable;
use ark_ec::ProjectiveCurve;
use ark_ff::One;
use ark_std::marker::PhantomData;
use crypto_primitives::error::CryptoError;
use crypto_primitives::zkp::proofs::chaum_pedersen_dl_equality;
use crypto_primitives::zkp::ArgumentOfKnowledge;
use std::ops::Mul;

pub struct RemaskingArgument<C> {
    _group: PhantomData<C>,
}

pub type CommonReferenceString<C> = chaum_pedersen_dl_equality::Parameters<C>;

pub struct Statement<C: ProjectiveCurve> {
    original: MaskedCard<C>,
    remasked: MaskedCard<C>,
}

impl<C: ProjectiveCurve> Statement<C> {
    pub fn new(original: MaskedCard<C>, remasked: MaskedCard<C>) -> Self {
        Self { original, remasked }
    }
}

impl<C: ProjectiveCurve> ArgumentOfKnowledge for RemaskingArgument<C> {
    type CommonReferenceString = CommonReferenceString<C>;
    type Statement = Statement<C>;
    type Witness = C::ScalarField;
    type Proof = ProofMasking<C>;

    fn prove(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, CryptoError> {

        // Build chaum-pedersen statement from our cards
        let minus_one = -C::ScalarField::one();
        let negative_original = statement.original.mul(minus_one);
        let statement_cipher = statement.remasked + negative_original;
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);

        chaum_pedersen_dl_equality::DLEquality::prove(
            common_reference_string,
            &cp_statement,
            &witness,
        )
    }

    fn verify(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
    ) -> Result<(), CryptoError> {
        // Build chaum-pedersen statement from our cards
        let minus_one = -C::ScalarField::one();
        let negative_original = statement.original.mul(minus_one);
        let statement_cipher = statement.remasked + negative_original;
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);

        chaum_pedersen_dl_equality::DLEquality::verify(
            common_reference_string,
            &cp_statement,
            proof,
        )
    }
}

impl<C: ProjectiveCurve> Verifiable<RemaskingArgument<C>> for ProofMasking<C> {
    fn verify_proof(
        &self,
        parameters: &CommonReferenceString<C>,
        statement: &Statement<C>,
    ) -> Result<(), CryptoError> {
        RemaskingArgument::verify(parameters, statement, self)
    }
}
