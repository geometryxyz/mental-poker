#[derive(Debug, PartialEq)]
pub enum Error {
    ProductArgumentProofError,
    ProductArgumentVerificationError,
    ZeroArgumentVerificationError,
    CommitmentError,
    DotProductLenError,
    TensorError,
    DimensionError,
    VerificationError,
    BilinearMapLenError,
    DiagonalLengthError,
}
