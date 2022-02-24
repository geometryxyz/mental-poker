#[derive(Debug, PartialEq)]
pub enum Error {
    ProductArgumentProofError,
    ProductArgumentVerificationError,
    ZeroArgumentVerificationError,
    HadamardProductLenError,
    CommitmentError,
    DotProductLenError,
    TensorError,
    DimensionError,
    VerificationError,
    BilinearMapLenError,
    DiagonalLengthError,
}
