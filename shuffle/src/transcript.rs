use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

pub(crate) trait TranscriptProtocol {
    fn append(&mut self, label: &'static [u8], item: &impl CanonicalSerialize);

    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F;
}

impl TranscriptProtocol for Transcript {
    fn append(&mut self, label: &'static [u8], item: &impl CanonicalSerialize) {
        let mut bytes = Vec::new();
        item.serialize(&mut bytes).unwrap();
        self.append_message(label, &bytes)
    }

    fn challenge_scalar<F>(&mut self, label: &'static [u8]) -> F
    where
        F: PrimeField,
    {
        let size = F::size_in_bits() / 8;
        let mut buf = vec![0u8; size];
        self.challenge_bytes(label, &mut buf);
        F::from_random_bytes(&buf).unwrap()
    }

}
