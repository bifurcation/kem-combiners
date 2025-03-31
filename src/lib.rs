// To benchmark
//
// 1. KitchenSink combiner
// 2. Chempat combiner
// 3. DHKEM combiner
// 4. XWing combiner
//
// 5. Hybrid with KitchenSink combiner
// 6. Hybrid with Chempat combiner
// 7. Hybrid with DHKEM combiner
// 8. Hybrid with XWing combiner

use hybrid_array::{sizes::U1088, Array};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Encoded, EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::CryptoRngCore;
use sha3::{digest::Output, Digest, Sha3_256};

pub trait Combiner {
    fn combine(
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
        ss_pq: &[u8],
        ct_pq: &[u8],
        ek_pq: &[u8],
    ) -> SharedSecret;
}

pub struct KitchenSink;

impl Combiner for KitchenSink {
    fn combine(
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
        ss_pq: &[u8],
        ct_pq: &[u8],
        ek_pq: &[u8],
    ) -> SharedSecret {
        let mut h = Sha3_256::new();
        h.update(ss_t);
        h.update(ct_t);
        h.update(ek_t);
        h.update(ss_pq);
        h.update(ct_pq);
        h.update(ek_pq);
        h.finalize()
    }
}

pub struct Chempat;

impl Combiner for Chempat {
    fn combine(
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
        ss_pq: &[u8],
        ct_pq: &[u8],
        ek_pq: &[u8],
    ) -> SharedSecret {
        let mut h = Sha3_256::new();

        h.update(ek_t);
        h.update(ek_pq);
        let hybrid_ek = h.finalize_reset();

        h.update(ct_t);
        h.update(ct_pq);
        let hybrid_ct = h.finalize_reset();

        h.update(ss_t);
        h.update(ss_pq);
        h.update(hybrid_ek);
        h.update(hybrid_ct);
        h.finalize()
    }
}

// Emulates doing a DHKEM-like derivation for each KEM
pub struct Dhkem;

impl Combiner for Dhkem {
    fn combine(
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
        ss_pq: &[u8],
        ct_pq: &[u8],
        ek_pq: &[u8],
    ) -> SharedSecret {
        let mut h = Sha3_256::new();

        h.update(ss_t);
        h.update(ct_t);
        h.update(ek_t);
        let input_t = h.finalize_reset();

        h.update(ss_pq);
        h.update(ct_pq);
        h.update(ek_pq);
        let input_pq = h.finalize_reset();

        h.update(input_t);
        h.update(input_pq);
        h.finalize()
    }
}

// Emulates doing DHKEM plus raw ML-KEM, X-Wing style
pub struct DhkemHalf;

impl Combiner for DhkemHalf {
    fn combine(
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
        ss_pq: &[u8],
        _ct_pq: &[u8],
        _ek_pq: &[u8],
    ) -> SharedSecret {
        let mut h = Sha3_256::new();

        h.update(ss_t);
        h.update(ct_t);
        h.update(ek_t);
        let input_t = h.finalize_reset();

        h.update(input_t);
        h.update(ss_pq);
        h.finalize()
    }
}

pub struct XWing;

impl Combiner for XWing {
    fn combine(
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
        ss_pq: &[u8],
        _ct_pq: &[u8],
        _ek_pq: &[u8],
    ) -> SharedSecret {
        let mut h = Sha3_256::new();
        h.update(ss_pq);
        h.update(ss_t);
        h.update(ct_t);
        h.update(ek_t);
        h.finalize()
    }
}

pub struct DecapsulationKey {
    pub t: x25519_dalek::StaticSecret,
    pub pq: <MlKem768 as KemCore>::DecapsulationKey,
    pub ek: EncapsulationKey,
}

#[derive(Clone)]
pub struct EncapsulationKey {
    pub t: x25519_dalek::PublicKey,
    pub pq: <MlKem768 as KemCore>::EncapsulationKey,
    pub pq_bytes: Encoded<<MlKem768 as KemCore>::EncapsulationKey>,
}

pub struct Ciphertext {
    pub t: x25519_dalek::PublicKey,
    pub pq: Array<u8, U1088>,
}

type SharedSecret = Output<Sha3_256>;

pub fn generate(rng: &mut impl CryptoRngCore) -> (DecapsulationKey, EncapsulationKey) {
    let dk_t = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
    let ek_t = x25519_dalek::PublicKey::from(&dk_t);

    let (dk_pq, ek_pq) = MlKem768::generate(&mut *rng);
    let pq_bytes = ek_pq.as_bytes();

    let ek = EncapsulationKey {
        t: ek_t,
        pq: ek_pq,
        pq_bytes,
    };
    let dk = DecapsulationKey {
        t: dk_t,
        pq: dk_pq,
        ek: ek.clone(),
    };
    (dk, ek)
}

pub fn encap<C>(rng: &mut impl CryptoRngCore, ek: &EncapsulationKey) -> (Ciphertext, SharedSecret)
where
    C: Combiner,
{
    let sk_e = x25519_dalek::EphemeralSecret::random_from_rng(&mut *rng);
    let ct_t = x25519_dalek::PublicKey::from(&sk_e);
    let ss_t = sk_e.diffie_hellman(&ek.t);

    let (ct_pq, ss_pq) = ek.pq.encapsulate(&mut *rng).unwrap();

    let ct = Ciphertext { t: ct_t, pq: ct_pq };
    let ss = C::combine(
        ss_t.as_bytes().as_slice(),
        ct.t.as_bytes().as_slice(),
        ek.t.as_bytes().as_slice(),
        ss_pq.as_ref(),
        ct.pq.as_ref(),
        ek.pq_bytes.as_slice(),
    );
    (ct, ss)
}

pub fn decap<C: Combiner>(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret
where
    C: Combiner,
{
    let ss_t = dk.t.diffie_hellman(&ct.t);
    let ss_pq = dk.pq.decapsulate(&ct.pq).unwrap();

    C::combine(
        ss_t.as_bytes().as_slice(),
        ct.t.as_bytes().as_slice(),
        dk.ek.t.as_bytes().as_slice(),
        ss_pq.as_ref(),
        ct.pq.as_ref(),
        dk.ek.pq_bytes.as_slice(),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_encap_decap<C: Combiner>() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = generate(&mut rng);
        let (ct, ss_e) = encap::<C>(&mut rng, &ek);
        let ss_d = decap::<C>(&dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn kitchen_sink() {
        test_encap_decap::<KitchenSink>();
    }

    #[test]
    fn chempat() {
        test_encap_decap::<Chempat>();
    }

    #[test]
    fn dhkem() {
        test_encap_decap::<Dhkem>();
    }

    #[test]
    fn dhkem_half() {
        test_encap_decap::<DhkemHalf>();
    }

    #[test]
    fn xwing() {
        test_encap_decap::<XWing>();
    }
}
