#[derive(Debug, PartialEq)]
pub enum Error {
    ProductArgumentProofError,
    ProductArgumentVerificationError,
    HadamardProductVerificationError,
    ZeroArgumentVerificationError,
    ZeroArgumentVerificationError1,
    ZeroArgumentVerificationError2,
    ZeroArgumentVerificationError3,
    HadamardProductLenError,
    CommitmentError,
    DotProductLenError,
    TensorError,
    DimensionError,
    VerificationError,
    BilinearMapLenError,
    DiagonalLengthError,
}
