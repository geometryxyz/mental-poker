use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

pub(crate) trait TranscriptProtocol {
    fn append(&mut self, label: &'static [u8], item: &impl CanonicalSerialize);

    fn challenge_scalar<F: Field>(&mut self, label: &'static [u8]) -> F;
}

impl TranscriptProtocol for Transcript {
    fn append(&mut self, label: &'static [u8], item: &impl CanonicalSerialize) {
        let mut bytes = Vec::new();
        item.serialize(&mut bytes).unwrap();
        self.append_message(label, &bytes)
    }

    fn challenge_scalar<F>(&mut self, label: &'static [u8]) -> F
    where
        F: Field,
    {
        let example = F::one();
        let size = example.serialized_size();
        // let size = F::size_in_bits() / 8;
        let mut buf = vec![0u8; size];
        self.challenge_bytes(label, &mut buf);
        F::from_random_bytes(&buf).unwrap()
    }
}

#[cfg(test)]
mod transcript_test {
    use ark_ff::One;
    use ark_serialize::CanonicalSerialize;
    use starknet_curve::Fr;
    #[test]
    fn f_size() {
        let one = Fr::one();
        let serialized_size = one.serialized_size();
        let uncompressed_size = one.uncompressed_size();

        // expect serialized_size&uncompressed_size to be same for the field
        assert_eq!(serialized_size, uncompressed_size);
    }
}
