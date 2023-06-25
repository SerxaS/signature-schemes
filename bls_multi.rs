use halo2curves::bn256::{G1, G2, Fr, pairing};
use halo2curves::ff::{Field, PrimeField, FromUniformBytes};
use halo2curves::group::Curve;
use rand::thread_rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::ops::{Mul, Add};

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

    //Serhas creates his public and private keys from Curve_1
    let serhas_sk = Fr::random(rng.clone());
    let serhas_pk = g1_fr_x.mul(serhas_sk.clone());   

    //Ronas creates his public and private keys from Curve_1
    let ronas_sk = Fr::random(rng.clone());
    let ronas_pk = g1_fr_x.mul(ronas_sk.clone()); 

    //Armanc creates his public and private keys from Curve_1
    let armanc_sk = Fr::random(rng.clone());
    let armanc_pk = g1_fr_x.mul(armanc_sk.clone()); 
        
    let message = "Serhas";
    let message_2 = "Ronas";
    let message_3 = "Armanc";
    
    //massages hashed
    let mut hasher = DefaultHasher::new();
    message.hash(&mut hasher);
    message_2.hash(&mut hasher);
    message_3.hash(&mut hasher);
    let hm = hasher.finish();

    //hashed massages moved from Curve_2's Fr into Curve_2 
    let hm_fr = Fr::from_u128(hm.into());
    let hm_fr_g2 = g2_fr_x.mul(hm_fr);
    let hm_g2 = g2_affine.mul(hm_fr_g2);
    let hm_g2_affine = hm_g2.to_affine();

    //Serhas signed message and signed massage moved into Curve_2
    let sigma_fr = serhas_sk.mul(hm_fr);
    let sigma_fr_g2 = g2_fr_x.mul(sigma_fr);
    let sigma_g2  = g2_affine.mul(sigma_fr_g2);
    let sigma_serhas_g2_affine = sigma_g2.to_affine();

    //Ronas signed message and signed massage moved into Curve_2
    let sigma_fr = ronas_sk.mul(hm_fr);
    let sigma_fr_g2 = g2_fr_x.mul(sigma_fr);
    let sigma_g2  = g2_affine.mul(sigma_fr_g2);
    let sigma_ronas_g2_affine = sigma_g2.to_affine();

    //Armanc signed message and signed massage moved into Curve_2
    let sigma_fr = armanc_sk.mul(hm_fr);
    let sigma_fr_g2 = g2_fr_x.mul(sigma_fr);
    let sigma_g2  = g2_affine.mul(sigma_fr_g2);
    let sigma_armanc_g2_affine = sigma_g2.to_affine();

    //Serhas public key moved from Curve_1's Fr into Curve_1
    let serhas_pk_fr_g1 = g1_fr_x.mul(serhas_pk);
    let serhas_pk_g1 = g1_affine.mul(serhas_pk_fr_g1);
    let serhas_pk_g1_affine = serhas_pk_g1.to_affine();

    //Ronas public key moved from Curve_1's Fr into Curve_1
    let ronas_pk_fr_g1 = g1_fr_x.mul(ronas_pk);
    let ronas_pk_g1 = g1_affine.mul(ronas_pk_fr_g1);
    let ronas_pk_g1_affine = ronas_pk_g1.to_affine();

    //Armanc public key moved from Curve_1's Fr into Curve_1
    let armanc_pk_fr_g1 = g1_fr_x.mul(armanc_pk);
    let armanc_pk_g1 = g1_affine.mul(armanc_pk_fr_g1);
    let armanc_pk_g1_affine = armanc_pk_g1.to_affine();

    //BLS signature 
    let mul_sigma = (sigma_serhas_g2_affine.add(sigma_ronas_g2_affine)).add(sigma_armanc_g2_affine);
    let mul_sigma_affine = mul_sigma.to_affine();

    let mul_pk = (serhas_pk_g1_affine.add(ronas_pk_g1_affine)).add(armanc_pk_g1_affine);
    let mul_pk_affine = mul_pk.to_affine();

    let pair_1 = pairing(&g1_affine, &mul_sigma_affine);
    let pair_2 = pairing(&mul_pk_affine, &hm_g2_affine);

    if pair_1 == pair_2 {
        println!("Signature matches.Serhas,Ronas and Armanc signed the message.")
    } else {
        println!("Invalid Signature!")
    }
}
