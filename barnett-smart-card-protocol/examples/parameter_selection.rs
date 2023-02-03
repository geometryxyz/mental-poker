//! An example that showcases how the prover time and proof size are affected by the parameter selection.
//! As per the Bayer-Groth paper, for a deck of $N = m \times n$ cards:
//! - the prover performs m*N exponentiations
//! - the proof is approximately 6m*|G|+4n*|Z| where |G| is the size of a EC point and |Z| is the size of a scalar
//! (note that this is because we are not using the FFT-like improvement suggested in the paper)
//! 
//! Analysis: increasing m will always increase the prover time. Assuming |G| ≈≈ 2*|Z|, proof size is approx 12m+4n and will
//! be minimised when m ≈≈ n/3.
//! 
//! Run the example `cargo run --example parameter_selection --release` and notice how proof size hits a minimum at m=10, n=30

use anyhow::anyhow;
use ark_ec::ProjectiveCurve;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use barnett_smart_card_protocol::discrete_log_cards::MaskedCard;
use barnett_smart_card_protocol::{discrete_log_cards, BarnettSmartProtocol};
use byte_unit::Byte;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use rand::{thread_rng, Rng};
use std::time::Instant;

// Choose elliptic curve setting
type Curve = ark_bls12_377::G1Projective;
type Scalar = ark_bls12_377::Fr;

// Instantiate concrete type for our card protocol
type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;

const NUMBER_OF_CARDS: usize = 300;

fn main() -> anyhow::Result<()> {
    let mut rng = thread_rng();

    let deck: Vec<MaskedCard<Curve>> = sample_vector(&mut rng, NUMBER_OF_CARDS);
    let shared_key = Curve::rand(&mut rng);
    let blinding_factors: Vec<Scalar> = sample_vector(&mut rng, NUMBER_OF_CARDS);
    let permutation = Permutation::new(&mut rng, NUMBER_OF_CARDS);

    let m_values: Vec<usize> = vec![2, 6, 10, 12, 30];
    let n_values: Vec<usize> = vec![150, 50, 30, 25, 10];

    for (&m, &n) in m_values.iter().zip(n_values.iter()) {
        benchmark_parameters(
            &deck,
            m,
            n,
            &shared_key,
            &blinding_factors,
            &permutation,
            &mut rng,
        )?;
    }

    Ok(())
}

fn benchmark_parameters<R: Rng>(
    deck: &Vec<MaskedCard<Curve>>,
    m: usize,
    n: usize,
    shared_key: &Curve,
    masking_factors: &Vec<Scalar>,
    permutation: &Permutation,
    rng: &mut R,
) -> anyhow::Result<()> {
    if deck.len() != m * n {
        return Err(anyhow!("Parameters do not match the deck size."));
    }

    println!("\n---------------------------------------------------");
    println!(
        "  Running a shuffle with parameters m = {} and n = {}",
        m, n
    );

    let parameters = CardProtocol::setup(rng, m, n)?;

    let prover_start_time = Instant::now();
    let (_shuffled_deck, proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &shared_key.into_affine(),
        deck,
        masking_factors,
        permutation,
    )?;
    let prover_end_time = Instant::now();
    let prover_duration = prover_end_time - prover_start_time;

    println!("    Prover time: {} seconds", prover_duration.as_secs_f32());
    println!(
        "    Proof size: {}\n",
        Byte::from_bytes(proof.serialized_size() as u128).get_appropriate_unit(false)
    );

    Ok(())
}
