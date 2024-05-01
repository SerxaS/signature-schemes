/// Signature scheme was made using https://2π.com/22/bls-signatures/
use halo2::halo2curves::{
    bn256::{pairing, Fr, G1, G2},
    ff::Field,
    group::Curve,
};

use crate::poseidon_hash::sponge::PoseidonSponge;
use rand::thread_rng;

pub struct BlsSig {
    pub(crate) alice_pub: G2,
    pub(crate) signature: G1,
}

impl BlsSig {
    pub fn sign(message: Fr) -> BlsSig {
        // Random number generator.
        let rng = thread_rng();

        // Alice's private and public key generation.
        let alice_priv = Fr::random(rng.clone());
        let alice_pub = G2::generator() * alice_priv;

        // Hashes message "m".
        let mut sponge = PoseidonSponge::new();
        sponge.update(&[message]);

        let msg_hash = PoseidonSponge::squeeze(&mut sponge);

        // Maps message "m" onto a point in group G2.
        let msg_g1 = G1::generator() * msg_hash;

        // Computes the signature.
        let signature = msg_g1 * alice_priv;

        BlsSig {
            alice_pub,
            signature,
        }
    }
}

pub fn bls_verify(message: Fr, sign: BlsSig) {
    // Hashes message "m"
    let mut sponge = PoseidonSponge::new();
    sponge.update(&[message]);

    let msg_hash = PoseidonSponge::squeeze(&mut sponge);

    // Given a signature and a public key, verifies that e(σ, g2) = e(pub_key, H(m)).
    if pairing(&sign.signature.to_affine(), &G2::generator().to_affine())
        == pairing(
            &(G1::generator() * msg_hash).to_affine(),
            &sign.alice_pub.to_affine(),
        )
    {
        println!("Signature matches. Alice signed the message.")
    } else {
        println!("Invalid Signature!")
    }
}
