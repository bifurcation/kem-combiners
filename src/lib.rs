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
        &self,
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
        &self,
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
        h.update(ss_t);
        h.update(ct_t);
        h.update(ss_pq);
        h.update(ct_pq);
        h.finalize()
    }
}

pub struct KitchenSinkPre {
    prefix: Sha3_256,
}

impl KitchenSinkPre {
    pub fn new(ek: &EncapsulationKey) -> Self {
        let mut prefix = Sha3_256::new();
        prefix.update(ek.t.as_bytes().as_slice());
        prefix.update(ek.pq_bytes.as_slice());
        Self { prefix }
    }
}

impl Combiner for KitchenSinkPre {
    fn combine(
        &self,
        ss_t: &[u8],
        ct_t: &[u8],
        _ek_t: &[u8],
        ss_pq: &[u8],
        ct_pq: &[u8],
        _ek_pq: &[u8],
    ) -> SharedSecret {
        let mut h = self.prefix.clone();
        h.update(ss_t);
        h.update(ct_t);
        h.update(ss_pq);
        h.update(ct_pq);
        h.finalize()
    }
}

pub struct Chempat;

impl Combiner for Chempat {
    fn combine(
        &self,
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

pub struct ChempatPre {
    hybrid_ek: Output<Sha3_256>,
}

impl ChempatPre {
    pub fn new(ek: &EncapsulationKey) -> Self {
        let mut h = Sha3_256::new();
        h.update(ek.t.as_bytes().as_slice());
        h.update(ek.pq_bytes.as_slice());

        Self {
            hybrid_ek: h.finalize(),
        }
    }
}

impl Combiner for ChempatPre {
    fn combine(
        &self,
        ss_t: &[u8],
        ct_t: &[u8],
        _ek_t: &[u8],
        ss_pq: &[u8],
        ct_pq: &[u8],
        _ek_pq: &[u8],
    ) -> SharedSecret {
        let mut h = Sha3_256::new();

        h.update(ct_t);
        h.update(ct_pq);
        let hybrid_ct = h.finalize_reset();

        h.update(ss_t);
        h.update(ss_pq);
        h.update(&self.hybrid_ek);
        h.update(hybrid_ct);
        h.finalize()
    }
}

// Emulates doing a DHKEM-like derivation for each KEM
pub struct Dhkem;

impl Combiner for Dhkem {
    fn combine(
        &self,
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
        ss_pq: &[u8],
        ct_pq: &[u8],
        ek_pq: &[u8],
    ) -> SharedSecret {
        let mut h = Sha3_256::new();

        h.update(ek_t);
        h.update(ss_t);
        h.update(ct_t);
        let input_t = h.finalize_reset();

        h.update(ek_pq);
        h.update(ss_pq);
        h.update(ct_pq);
        let input_pq = h.finalize_reset();

        h.update(input_t);
        h.update(input_pq);
        h.finalize()
    }
}

// Stateful DHKEM-like derivation, with a pre-hashed public-key prefix for each algorithm
pub struct DhkemPre {
    prefix_t: Sha3_256,
    prefix_pq: Sha3_256,
}

impl DhkemPre {
    pub fn new(ek: &EncapsulationKey) -> Self {
        let mut prefix_t = Sha3_256::new();
        prefix_t.update(ek.t.as_bytes().as_slice());

        let mut prefix_pq = Sha3_256::new();
        prefix_pq.update(ek.pq_bytes.as_slice());

        Self {
            prefix_t,
            prefix_pq,
        }
    }
}

impl Combiner for DhkemPre {
    fn combine(
        &self,
        ss_t: &[u8],
        ct_t: &[u8],
        _ek_t: &[u8],
        ss_pq: &[u8],
        ct_pq: &[u8],
        _ek_pq: &[u8],
    ) -> SharedSecret {
        let mut t = self.prefix_t.clone();
        t.update(ss_t);
        t.update(ct_t);

        let mut pq = self.prefix_pq.clone();
        pq.update(ss_pq);
        pq.update(ct_pq);

        let mut h = Sha3_256::new();
        h.update(t.finalize());
        h.update(pq.finalize());
        h.finalize()
    }
}

// Emulates doing DHKEM plus raw ML-KEM, X-Wing style
pub struct DhkemHalf;

impl Combiner for DhkemHalf {
    fn combine(
        &self,
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
        &self,
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

pub fn encap<C: Combiner>(
    c: &C,
    rng: &mut impl CryptoRngCore,
    ek: &EncapsulationKey,
) -> (Ciphertext, SharedSecret) {
    let sk_e = x25519_dalek::EphemeralSecret::random_from_rng(&mut *rng);
    let ct_t = x25519_dalek::PublicKey::from(&sk_e);
    let ss_t = sk_e.diffie_hellman(&ek.t);

    let (ct_pq, ss_pq) = ek.pq.encapsulate(&mut *rng).unwrap();

    let ct = Ciphertext { t: ct_t, pq: ct_pq };
    let ss = c.combine(
        ss_t.as_bytes().as_slice(),
        ct.t.as_bytes().as_slice(),
        ek.t.as_bytes().as_slice(),
        ss_pq.as_ref(),
        ct.pq.as_ref(),
        ek.pq_bytes.as_slice(),
    );
    (ct, ss)
}

pub fn decap<C: Combiner>(c: &C, dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
    let ss_t = dk.t.diffie_hellman(&ct.t);
    let ss_pq = dk.pq.decapsulate(&ct.pq).unwrap();

    c.combine(
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

    fn key_pair() -> (DecapsulationKey, EncapsulationKey) {
        let mut rng = rand::thread_rng();
        generate(&mut rng)
    }

    fn test_encap_decap<C: Combiner>(c: &C, dk: DecapsulationKey, ek: EncapsulationKey) {
        let mut rng = rand::thread_rng();
        let (ct, ss_e) = encap(c, &mut rng, &ek);
        let ss_d = decap(c, &dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn kitchen_sink() {
        let (dk, ek) = key_pair();
        test_encap_decap(&KitchenSink, dk, ek);
    }

    #[test]
    fn kitchen_sink_pre() {
        let (dk, ek) = key_pair();
        let kitchen_sink_pre = KitchenSinkPre::new(&ek);
        test_encap_decap(&kitchen_sink_pre, dk, ek);
    }

    #[test]
    fn kitchen_sink_pre_eq() {
        let (dk, ek) = key_pair();
        let kitchen_sink = KitchenSink;
        let kitchen_sink_pre = KitchenSinkPre::new(&ek);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = encap(&kitchen_sink, &mut rng, &ek);
        let ss_d = decap(&kitchen_sink_pre, &dk, &ct);
        assert_eq!(ss_e, ss_d);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = encap(&kitchen_sink_pre, &mut rng, &ek);
        let ss_d = decap(&kitchen_sink, &dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn chempat() {
        let (dk, ek) = key_pair();
        test_encap_decap(&Chempat, dk, ek);
    }

    #[test]
    fn chempat_pre() {
        let (dk, ek) = key_pair();
        let chempat_pre = ChempatPre::new(&ek);
        test_encap_decap(&chempat_pre, dk, ek);
    }

    #[test]
    fn chempat_pre_eq() {
        let (dk, ek) = key_pair();
        let chempat = Chempat;
        let chempat_pre = ChempatPre::new(&ek);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = encap(&chempat, &mut rng, &ek);
        let ss_d = decap(&chempat_pre, &dk, &ct);
        assert_eq!(ss_e, ss_d);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = encap(&chempat_pre, &mut rng, &ek);
        let ss_d = decap(&chempat, &dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn dhkem() {
        let (dk, ek) = key_pair();
        test_encap_decap(&Dhkem, dk, ek);
    }

    #[test]
    fn dhkem_pre() {
        let (dk, ek) = key_pair();
        let dhkem_pre = DhkemPre::new(&ek);
        test_encap_decap(&dhkem_pre, dk, ek);
    }

    #[test]
    fn dhkem_pre_eq() {
        let (dk, ek) = key_pair();
        let dhkem = Dhkem;
        let dhkem_pre = DhkemPre::new(&ek);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = encap(&dhkem, &mut rng, &ek);
        let ss_d = decap(&dhkem_pre, &dk, &ct);
        assert_eq!(ss_e, ss_d);

        let mut rng = rand::thread_rng();
        let (ct, ss_e) = encap(&dhkem_pre, &mut rng, &ek);
        let ss_d = decap(&dhkem, &dk, &ct);
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn dhkem_half() {
        let (dk, ek) = key_pair();
        test_encap_decap(&DhkemHalf, dk, ek);
    }

    #[test]
    fn xwing() {
        let (dk, ek) = key_pair();
        test_encap_decap(&XWing, dk, ek);
    }
}
