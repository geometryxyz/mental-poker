use super::{Card, MaskedCard, ProofMasking};
use crate::Verifiable;
use ark_ec::ProjectiveCurve;
use ark_ff::One;
use ark_std::marker::PhantomData;
use crypto_primitives::error::CryptoError;
use crypto_primitives::zkp::proofs::chaum_pedersen_dl_equality;
use crypto_primitives::zkp::ArgumentOfKnowledge;
use std::ops::Mul;

pub struct MaskingArgument<C> {
    _group: PhantomData<C>,
}

pub type CommonReferenceString<C> = chaum_pedersen_dl_equality::Parameters<C>;

pub struct Statement<C: ProjectiveCurve>(pub Card<C>, pub MaskedCard<C>);

impl<C: ProjectiveCurve> ArgumentOfKnowledge for MaskingArgument<C> {
    type CommonReferenceString = CommonReferenceString<C>;
    type Statement = Statement<C>;
    type Witness = C::ScalarField;
    type Proof = ProofMasking<C>;

    fn prove(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, CryptoError> {
        let card = statement.0;
        let masked = statement.1;

        // Build chaum-pedersen statement from our cards
        let minus_one = -C::ScalarField::one();
        let negative_message = card.mul(minus_one).0;
        let statement_cipher = negative_message + masked.1;
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&masked.0, &statement_cipher);

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
        let card = statement.0;
        let masked = statement.1;

        // Build chaum-pedersen statement from our cards
        let minus_one = -C::ScalarField::one();
        let negative_message = card.mul(minus_one).0;
        let statement_cipher = negative_message + masked.1;
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&masked.0, &statement_cipher);

        chaum_pedersen_dl_equality::DLEquality::verify(
            common_reference_string,
            &cp_statement,
            proof,
        )
    }
}

impl<C: ProjectiveCurve> Verifiable<MaskingArgument<C>> for ProofMasking<C> {
    fn verify_proof(
        &self,
        parameters: &CommonReferenceString<C>,
        statement: &Statement<C>,
    ) -> Result<(), CryptoError> {
        MaskingArgument::verify(parameters, statement, self)
    }
}
