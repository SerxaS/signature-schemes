/// Signature scheme was made using https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
use halo2::halo2curves::{
    bn256::{Fr, G1},
    ff::Field,
};
use rand::thread_rng;

use crate::poseidon_hash::sponge::PoseidonSponge;

pub struct SchMuSig {
    pub(crate) big_r_alice: G1,
    pub(crate) s_alice: Fr,
    pub(crate) alice_pub: G1,
    pub(crate) big_r_bob: G1,
    pub(crate) s_bob: Fr,
    pub(crate) bob_pub: G1,
}

impl SchMuSig {
    pub fn signature(alice_msg: Fr, bob_msg: Fr) -> SchMuSig {
        // Random number generator.
        let rng = thread_rng();

        // Alice's private and public key generation.
        let alice_priv = Fr::random(rng.clone());
        let alice_pub = G1::generator() * alice_priv;

        // Bob's private and public key generation.
        let bob_priv = Fr::random(rng.clone());
        let bob_pub = G1::generator() * bob_priv;

        // Alice chooses a random number "r" and generates "R".
        let r_alice = Fr::random(rng.clone());
        let big_r_alice = G1::generator() * r_alice;

        // Bob chooses a random number "r" and generates "R".
        let r_bob = Fr::random(rng.clone());
        let big_r_bob = G1::generator() * r_bob;

        // To protect against attacks, we choose key prefixed Schnorr signatures which
        // means that the public key is prefixed to the message in the challenge hash input.
        // Concatenates "r", "pub key" and "message" separately and hashes them.
        let alice_pub_fr = Fr::from_bytes(&alice_pub.x.to_bytes()).unwrap();
        let big_r_alice_fr = Fr::from_bytes(&big_r_alice.x.to_bytes()).unwrap();

        let bob_pub_fr = Fr::from_bytes(&bob_pub.x.to_bytes()).unwrap();
        let big_r_bob_fr = Fr::from_bytes(&big_r_bob.x.to_bytes()).unwrap();

        let mut sponge = PoseidonSponge::new();

        sponge.update(&[big_r_alice_fr, alice_pub_fr, alice_msg]);
        let e_alice = PoseidonSponge::squeeze(&mut sponge);

        sponge.update(&[big_r_bob_fr, bob_pub_fr, bob_msg]);
        let e_bob = PoseidonSponge::squeeze(&mut sponge);

        // Calculates "s" value
        let s_alice = r_alice + (e_alice * alice_priv);
        let s_bob = r_bob + (e_bob * bob_priv);

        SchMuSig {
            big_r_alice,
            s_alice,
            alice_pub,
            big_r_bob,
            s_bob,
            bob_pub,
        }
    }
}

pub fn sch_musig_verify(alice_msg: Fr, bob_msg: Fr, signature: SchMuSig) {
    // Random number generator.
    let rng = thread_rng();

    // Generates random integers "a". For safety of adding invalid signatures.
    let alice_rnd_a = Fr::random(rng.clone());
    let bob_rnd_a = Fr::random(rng.clone());

    // Concatenates "r", "pub key" and "message" separately and hashes them.
    let alice_pub_fr = Fr::from_bytes(&signature.alice_pub.x.to_bytes()).unwrap();
    let big_r_alice_fr = Fr::from_bytes(&signature.big_r_alice.x.to_bytes()).unwrap();

    let bob_pub_fr = Fr::from_bytes(&signature.bob_pub.x.to_bytes()).unwrap();
    let big_r_bob_fr = Fr::from_bytes(&signature.big_r_bob.x.to_bytes()).unwrap();

    let mut sponge = PoseidonSponge::new();

    sponge.update(&[big_r_alice_fr, alice_pub_fr, alice_msg]);
    let e_v_alice = PoseidonSponge::squeeze(&mut sponge);

    sponge.update(&[big_r_bob_fr, bob_pub_fr, bob_msg]);
    let e_v_bob = PoseidonSponge::squeeze(&mut sponge);

    // Verifies that the equation holds.
    if G1::generator() * (alice_rnd_a * signature.s_alice + bob_rnd_a * signature.s_bob)
        == ((signature.alice_pub * alice_rnd_a * e_v_alice)
            + (signature.bob_pub * bob_rnd_a * e_v_bob))
            + (signature.big_r_alice * alice_rnd_a + signature.big_r_bob * bob_rnd_a)
    {
        println!("Signature matches. They signed the message.")
    } else {
        println!("Invalid Signature!")
    }
}
