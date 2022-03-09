use ark_ff::{
    biginteger::BigInteger256 as BigInteger,
    fields::{FftParameters, Fp256, Fp256Parameters, FpParameters},
};

pub struct FrParameters;

pub type Fr = Fp256<FrParameters>;

impl Fp256Parameters for FrParameters {}
impl FftParameters for FrParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 1;

    // TWO_ADIC_ROOT_OF_UNITY = GENERATOR^T
    // Encoded in Montgomery form, so the value here is (3^T)R mod q.
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger::new([
        0xccd44835b8c9a5e0,
        0xf0224db95cf64643,
        0xfffffffffffffff6,
        0x000000000000021f,
    ]);
}

impl FpParameters for FrParameters {
    // 3618502788666131213697322783095070105526743751716087489154079457884512865583
    const MODULUS: BigInteger = BigInteger::new([
        0x1e66a241adc64d2f,
        0xb781126dcae7b232,
        0xffffffffffffffff,
        0x0800000000000010,
    ]);

    // R = 2^256 mod q
    const R: BigInteger = BigInteger::new([
        0x51925a0bf4fca74f,
        0xc75ec4b46df16bee,
        0x0000000000000008,
        0x07fffffffffffdf1,
    ]);

    // R2 = (2^256)^2 mod q
    const R2: BigInteger = BigInteger::new([
        0x6021b3f1ea1c688d,
        0x509cf64d14ce60b9,
        0xbaf0ab4cf78bbabb,
        0x07d9e57c2333766e,
    ]);

    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
        0x0f335120d6e32697,
        0xdbc08936e573d919,
        0x7fffffffffffffff,
        0x0400000000000008,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T

    const T: BigInteger = BigInteger::new([
        0x0f335120d6e32697,
        0xdbc08936e573d919,
        0x7fffffffffffffff,
        0x0400000000000008,
    ]);

    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
        0x8799a8906b71934b,
        0xede0449b72b9ec8c,
        0x3fffffffffffffff,
        0x0200000000000004,
    ]);

    // GENERATOR = 3
    // Encoded in Montgomery form, so the value here is 3R mod q.
    const GENERATOR: BigInteger = BigInteger::new([
        0xb7e9c9a083695b8f,
        0xe71a2941b404df66,
        0x000000000000001a,
        0x07fffffffffff9b1,
    ]);

    const MODULUS_BITS: u32 = 251;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 5;

    // INV = -q^{-1} (mod 2^64)
    const INV: u64 = 13504954208620504625;
}
