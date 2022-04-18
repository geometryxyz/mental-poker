use ark_ff::{
    biginteger::BigInteger256 as BigInteger,
    fields::{FftParameters, Fp256, Fp256Parameters},
};

pub type Fq = Fp256<FqParameters>;

pub struct FqParameters;

impl Fp256Parameters for FqParameters {}
// FFT is not supported for TWO_ADICITY greater than 64, so we won't use FFTs in this particular field: https://github.com/arkworks-rs/algebra/issues/313
impl FftParameters for FqParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 192;

    // TWO_ADIC_ROOT_OF_UNITY = GENERATOR^T
    // Encoded in Montgomery form, so the value here is (3^T)R mod p.
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger::new([
        0x4106bccd64a2bdd8,
        0xaaada25731fe3be9,
        0x0a35c5be60505574,
        0x07222e32c47afc26,
    ]);
}

impl ark_ff::fields::FpParameters for FqParameters {
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const MODULUS: BigInteger = BigInteger::new([
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0800000000000011,
    ]);

    // R = 2^256 mod p
    const R: BigInteger = BigInteger::new([
        0xffffffffffffffe1,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x07fffffffffffdf0,
    ]);

    // R2 = (2^256)^2 mod p
    const R2: BigInteger = BigInteger::new([
        0xfffffd737e000401,
        0x00000001330fffff,
        0xffffffffff6f8000,
        0x07ffd4ab5e008810,
    ]);

    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
        0x0000000000000000,
        0x0000000000000000,
        0x8000000000000000,
        0x0400000000000008,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T
    const T: BigInteger = BigInteger::new([
        0x0800000000000011,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]);

    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
        0x0400000000000008,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]);

    // GENERATOR = 3
    // Encoded in Montgomery form, so the value here is 3R mod p.
    const GENERATOR: BigInteger = BigInteger::new([
        0xffffffffffffffa1,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x07fffffffffff9b0,
    ]);

    const MODULUS_BITS: u32 = 252;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 4;

    // INV = -p^{-1} (mod 2^64)
    const INV: u64 = 18446744073709551615;
}
