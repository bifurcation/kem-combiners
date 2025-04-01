use hybrid_array::{sizes::U1088, Array};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Encoded, EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::CryptoRngCore;

use crate::combiners::NewPre;
use crate::{Combiner, SharedSecret};

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

pub trait NewMlKem {
    fn new_ml_kem(ek: &EncapsulationKey) -> Self;
}

impl<T> NewMlKem for T
where
    T: NewPre,
{
    fn new_ml_kem(ek: &EncapsulationKey) -> Self {
        Self::new_pre(ek.t.as_bytes().as_slice(), ek.pq_bytes.as_slice())
    }
}

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
    use crate::combiners::*;

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
        let kitchen_sink_pre = KitchenSinkPre::new_ml_kem(&ek);
        test_encap_decap(&kitchen_sink_pre, dk, ek);
    }

    #[test]
    fn kitchen_sink_pre_eq() {
        let (dk, ek) = key_pair();
        let kitchen_sink = KitchenSink;
        let kitchen_sink_pre = KitchenSinkPre::new_ml_kem(&ek);

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
        let chempat_pre = ChempatPre::new_ml_kem(&ek);
        test_encap_decap(&chempat_pre, dk, ek);
    }

    #[test]
    fn chempat_pre_eq() {
        let (dk, ek) = key_pair();
        let chempat = Chempat;
        let chempat_pre = ChempatPre::new_ml_kem(&ek);

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
        let dhkem_pre = DhkemPre::new_ml_kem(&ek);
        test_encap_decap(&dhkem_pre, dk, ek);
    }

    #[test]
    fn dhkem_pre_eq() {
        let (dk, ek) = key_pair();
        let dhkem = Dhkem;
        let dhkem_pre = DhkemPre::new_ml_kem(&ek);

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
