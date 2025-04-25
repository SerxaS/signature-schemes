#[cfg(test)]
mod test {
    use crate::signatures::{
        bls_musig::{bls_musig_verify, BlsMuSig},
        bls_single::{bls_verify, BlsSig},
        schnorr_batch_verify::{schnorr_batch_verify, SchnorrBatch},
        schnorr_single::{sch_verify, SchSign},
    };
    use halo2::halo2curves::{bn256::Fr, ff::Field};
    use rand::thread_rng;

    #[test]
    fn schnorr_test() {
        // Random number generator.
        let rng = thread_rng();

        // Message that wants to sign.
        let tx_num = Fr::random(rng.clone());

        // Alice signs message.
        let signature = SchSign::signature(tx_num);

        // Bob verifies Alice's signature that signed from herself.
        sch_verify(tx_num, signature);
    }

    #[test]
    fn schnorr_batch_verify_test() {
        // Random number generator.
        let rng = thread_rng();

        // Message that wants to sign.
        let alice_tx_num = Fr::random(rng.clone());
        let bob_tx_num = Fr::random(rng.clone());

        // Alice signs message.
        let signature = SchnorrBatch::signature(alice_tx_num, bob_tx_num);

        // Bob verifies Alice's signature that signed from herself.
        schnorr_batch_verify(alice_tx_num, bob_tx_num, signature);
    }

    #[test]
    fn bls_test() {
        // Random number generator.
        let rng = thread_rng();

        // Message that wants to sign.
        let tx_num = Fr::random(rng.clone());

        // Alice signs message.
        let signature = BlsSig::sign(tx_num);

        // Bob verifies Alice's signature that signed from herself.
        bls_verify(tx_num, signature);
    }

    #[test]
    fn bls_musig_test() {
        // Random number generator.
        let rng = thread_rng();

        // Message that wants to sign.
        let alice_tx_num = Fr::random(rng.clone());
        let bob_tx_num = Fr::random(rng.clone());

        // Alice signs message.
        let signature = BlsMuSig::sign(alice_tx_num, bob_tx_num);

        // Bob verifies Alice's signature that signed from herself.
        bls_musig_verify(alice_tx_num, bob_tx_num, signature);
    }
}
