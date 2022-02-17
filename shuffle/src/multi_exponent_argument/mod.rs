use verifiable_threshold_masking_protocol::discrete_log_vtmp::{ElgamalCipher};
use ark_ec::{ProjectiveCurve};
use ark_ff::{Zero};

pub mod error;

use error::Error;

pub fn diagonal_sums_of_tensor_prod<C: ProjectiveCurve>(
    ciphers: &Vec<ElgamalCipher<C>>,
    scalars: &Vec<C::ScalarField>,
    m: usize, n: usize) -> Result<Vec<ElgamalCipher<C>>, Error > {

    if ciphers.len() % m != 0 || scalars.len() % m != 0 {
        return Err(Error::DimensionError)
    }

    let n_try: usize = ciphers.len() / m;
    assert_eq!(n_try, n);

    let c_chunks = ciphers.chunks(n).map(|c| c.to_vec()).collect::<Vec<_>>();
    let a_chunks = scalars.chunks(n).map(|c| c.to_vec()).collect::<Vec<_>>();

    println!("{:?}", a_chunks);
    
    let num_of_diagonals = 2 * m - 1;

    let mut diagonal_sums: Vec<ElgamalCipher<C>> = vec![ElgamalCipher::zero(); num_of_diagonals];
    let center = num_of_diagonals/2 as usize;

    for d in 1..m {
        let mut tmp_product1 = ElgamalCipher::zero(); 
        let mut tmp_product2 = ElgamalCipher::zero(); 
        for i in d..m {
            let dot = dot_product(&c_chunks[i], &a_chunks[i - d]).unwrap();
            tmp_product1 = tmp_product1 + dot;

            let dot = dot_product(&c_chunks[i - d], &a_chunks[i]).unwrap();
            tmp_product2 = tmp_product2 + dot;
        }

        println!("{}, {}, {}", center, d, m);
        diagonal_sums[center - d] = tmp_product1;
        diagonal_sums[center + d] = tmp_product2;
    }

    //TODO put our stated product here
    diagonal_sums[center] = ElgamalCipher::zero();

    Ok(diagonal_sums)    
}

pub fn dot_product<C: ProjectiveCurve>(
    ciphers: &Vec<ElgamalCipher<C>>,
    scalars: &Vec<C::ScalarField>)
    -> Result<ElgamalCipher<C>, Error> {
    
    if ciphers.len() != scalars.len() {
        return Err(Error::DotProductLenError)
    }

    let product: ElgamalCipher<C> = ciphers.iter().zip(scalars.iter()).map(|(cipher, scalar)| *cipher * *scalar).sum();

    Ok(product)
}

#[cfg(test)]
mod test {

    use starknet_curve::{Projective, Fr, Affine};
    use ark_std::{rand::{thread_rng}, UniformRand};
    use verifiable_threshold_masking_protocol::discrete_log_vtmp::{ElgamalCipher};
    use super::{dot_product, diagonal_sums_of_tensor_prod};
    use ark_ff::{Zero};

    #[test]
    fn test_dot_product() {
        let rng = &mut thread_rng();
        
        let c1 = ElgamalCipher::<Projective>(Projective::rand(rng).into(), Projective::rand(rng).into());
        let c2 = ElgamalCipher::<Projective>(Projective::rand(rng).into(), Projective::rand(rng).into());
        let c3 = ElgamalCipher::<Projective>(Projective::rand(rng).into(), Projective::rand(rng).into());


        let c = vec![c1, c2, c3];

        let scalars = vec![Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];

        let manual_dot_product = c1 * scalars[0] + c2 * scalars[1] + c3 * scalars[2];

        assert_eq!(manual_dot_product, dot_product(&c, &scalars).unwrap());
    }

    #[test]
    fn test_diagonal_sums() {
        let m = 3;
        let n = 2;
        let rng = &mut thread_rng();

        let number_of_ciphers = m*n;

        let mut ciphers: Vec<ElgamalCipher<Projective>> = vec![ElgamalCipher::zero(); number_of_ciphers];
        let mut scalars: Vec<Fr> = vec![Fr::zero(); number_of_ciphers];

        let test_cipher = ElgamalCipher::<Projective>(Projective::rand(rng).into(), Projective::rand(rng).into());

        for i in 0..number_of_ciphers {
            ciphers[i] = test_cipher.clone();
            scalars[i] = Fr::rand(rng);
        }
        
        let result = diagonal_sums_of_tensor_prod(&ciphers, &scalars, m, n).unwrap();

        let manual_result = vec![
            test_cipher * (scalars[0] + scalars[1]),
            test_cipher * (scalars[0] + scalars[1] + scalars[2] + scalars[3]),
            ElgamalCipher::zero(),
            test_cipher * (scalars[2] + scalars[3] + scalars[4] + scalars[5]),
            test_cipher * (scalars[4] + scalars[5])
        ];

        assert_eq!(result, manual_result);
    }
}