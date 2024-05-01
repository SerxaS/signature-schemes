/// Signature scheme was made using https://2π.com/22/bls-signatures/
use halo2::halo2curves::{
    bn256::{pairing, Fr, G1, G2},
    ff::Field,
    group::Curve,
};

use crate::poseidon_hash::sponge::PoseidonSponge;
use rand::thread_rng;

pub struct BlsMuSig {
    pub(crate) alice_pub: G2,
    pub(crate) bob_pub: G2,
    pub(crate) agg_sig: G1,
}

impl BlsMuSig {
    pub fn sign(alice_msg: Fr, bob_msg: Fr) -> BlsMuSig {
        // Random number generator.
        let rng = thread_rng();

        // Alice's private and public key generation.
        let alice_priv = Fr::random(rng.clone());
        let alice_pub = G2::generator() * alice_priv;

        // Bob's private and public key generation.
        let bob_priv = Fr::random(rng.clone());
        let bob_pub = G2::generator() * bob_priv;

        // Both hashes their message "m".
        let mut sponge = PoseidonSponge::new();

        sponge.update(&[alice_msg]);
        let alice_msg_hash = PoseidonSponge::squeeze(&mut sponge);

        sponge.update(&[bob_msg]);
        let bob_msg_hash = PoseidonSponge::squeeze(&mut sponge);

        // Maps message "m" onto a point in group G2
        let alice_msg_g1 = G1::generator() * alice_msg_hash;
        let bob_msg_g1 = G1::generator() * bob_msg_hash;

        // Computes the aggregated signature.
        let agg_sig = (alice_msg_g1 * alice_priv) + (bob_msg_g1 * bob_priv);

        BlsMuSig {
            alice_pub,
            bob_pub,
            agg_sig,
        }
    }
}

pub fn bls_musig_verify(alice_msg: Fr, bob_msg: Fr, sign: BlsMuSig) {
    // Both hashes their message "m".
    let mut sponge = PoseidonSponge::new();

    sponge.update(&[alice_msg]);
    let alice_msg_hash = PoseidonSponge::squeeze(&mut sponge);

    sponge.update(&[bob_msg]);
    let bob_msg_hash = PoseidonSponge::squeeze(&mut sponge);

    // Given a signature and a public key, verifies that
    // e(σ_agg ,g2) = e(H(m)_1, pub_key_1) + e(H(m)_2, pub_key_2).
    if pairing(&sign.agg_sig.to_affine(), &G2::generator().to_affine())
        == pairing(
            &(G1::generator() * alice_msg_hash).to_affine(),
            &sign.alice_pub.to_affine(),
        ) + pairing(
            &(G1::generator() * bob_msg_hash).to_affine(),
            &sign.bob_pub.to_affine(),
        )
    {
        println!("Signature matches. They signed the message.")
    } else {
        println!("Invalid Signature!")
    }
}
