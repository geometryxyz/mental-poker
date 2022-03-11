use ark_ff::Field;

pub trait FromField<F: Field> {
    fn from_field(x: F) -> Self;
}

pub trait ToField<F: Field> {
    fn into_field(self) -> F;
}

pub trait MulByScalar<F: Field, Rhs: ToField<F>> {
    type Output;

    fn mul(self, rhs: Rhs) -> Self::Output;
    fn mul_in_place(&mut self, rhs: Rhs);
}
