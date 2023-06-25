
use halo2curves::bn256::{G1, Fr};
use halo2curves::ff::{Field, PrimeField};
use halo2curves::group::Curve;
use rand::thread_rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::ops::{Mul, Add};


fn main() {
    //G1 moved into Fr
    let generator = G1::generator();
    let generator_affine = generator.to_affine();
    let generator_x = generator_affine.x.to_bytes();
    let generator_fr_x = Fr::from_bytes(&generator_x).unwrap();

    //For random number generator
    let rng = thread_rng();

    //Alice created her public and private keys
    let alice_private_key = Fr::random(rng.clone());
    let alice_public_key = generator_fr_x.mul(alice_private_key.clone()); 

    //Alice picked up a nonce "r" value and creates a "R" value
    let nonce_r = Fr::random(rng.clone());
    let big_r = generator_fr_x.mul(nonce_r.clone());
        
    //Concatenated "R" value and "message", then calculated hash of them "e" 
    let message = "Serhas";

    let mut hasher = DefaultHasher::new();
    big_r.hash(&mut hasher);
    message.hash(&mut hasher);
    let e = hasher.finish();

    //"e" moved into Fr
    let e_fr = Fr::from_u128(e.into());

    //Calculated "s" value
    let s = (e_fr.mul(alice_private_key)).add(nonce_r);

    //Sended her "public key", "message", "R" and "s" to Bob. 
    //Bob calculated bob_s = (s*G) and "e_fr", and compared it to bob_sc = (R + e*Pa)
   
    let bob_s = generator_fr_x.mul(s);
    let bob_sc =  (alice_public_key.mul(e_fr)).add(big_r);

    if bob_sc == bob_s {
        println!("Signature matches.Alice signed the message.")
    } else {
        println!("Invalid Signature!")
    }
}
