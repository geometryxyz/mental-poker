#[derive(Debug, PartialEq)]
pub enum Error {
    SetupError,
    KeyGenError,
    MaskingError,
}
