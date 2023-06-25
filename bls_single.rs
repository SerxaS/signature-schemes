use halo2curves::bn256::{G1, G2, Fr, pairing};
use halo2curves::ff::{Field, PrimeField, FromUniformBytes};
use halo2curves::group::Curve;
use rand::thread_rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::ops::Mul;

fn main() {
    //G1 from Curve_1 moved into Curve_1's Fr
    let g1 = G1::generator();
    let g1_affine = g1.to_affine();
    let g1_x = g1_affine.x.to_bytes();
    let g1_fr_x = Fr::from_bytes(&g1_x).unwrap();

    //G2 from Curve_2 moved into Curve_2's Fr
    let g2 = G2::generator();
    let g2_affine = g2.to_affine();
    let g2_x = g2_affine.x.to_bytes();
    let g2_fr_x = Fr::from_uniform_bytes(&g2_x);        

    //for random number generator
    let rng = thread_rng();

    //Alice creates her public and private keys from Curve_1
    let alice_sk = Fr::random(rng.clone());
    let alice_pk = g1_fr_x.mul(alice_sk.clone());    
        
    let message = "Serhas";
    
    //massage hashed
    let mut hasher = DefaultHasher::new();
    message.hash(&mut hasher);
    let hm = hasher.finish();

    //hashed massage moved from Curve_2's Fr into Curve_2 
    let hm_fr = Fr::from_u128(hm.into());
    let hm_fr_g2 = g2_fr_x.mul(hm_fr);
    let hm_g2 = g2_affine.mul(hm_fr_g2);
    let hm_g2_affine = hm_g2.to_affine();

    //Alice signed message and signed massage moved into Curve_2
    let sigma_fr = alice_sk.mul(hm_fr);
    let sigma_fr_g2 = g2_fr_x.mul(sigma_fr);
    let sigma_g2  = g2_affine.mul(sigma_fr_g2);
    let sigma_g2_affine = sigma_g2.to_affine();

    //Alice public key moved from Curve_1's Fr into Curve_1
    let alice_pk_fr_g1 = g1_fr_x.mul(alice_pk);
    let alice_pk_g1 = g1_affine.mul(alice_pk_fr_g1);
    let alice_pk_g1_affine = alice_pk_g1.to_affine();

    //BLS signature  
    let pair_1 = pairing(&g1_affine, &sigma_g2_affine);
    let pair_2 = pairing(&alice_pk_g1_affine, &hm_g2_affine);

    if pair_1 == pair_2 {
        println!("Signature matches.Alice signed the message.")
    } else {
        println!("Invalid Signature!")
    }
}
