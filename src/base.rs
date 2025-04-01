use hybrid_array::{
    sizes::{U1088, U32},
    Array,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Encoded, EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::CryptoRngCore;

pub trait BaseKem {
    type DecapsulationKey;
    type EncapsulationKey: Clone + AsRef<[u8]>;
    type Ciphertext: AsRef<[u8]>;
    type SharedSecret: AsRef<[u8]>;

    fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey);

    fn encap(
        rng: &mut impl CryptoRngCore,
        ek: &Self::EncapsulationKey,
    ) -> (Self::Ciphertext, Self::SharedSecret);

    fn decap(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Self::SharedSecret;
}

// Raw X25519
pub struct X25519;

impl BaseKem for X25519 {
    type DecapsulationKey = x25519_dalek::StaticSecret;
    type EncapsulationKey = x25519_dalek::PublicKey;
    type Ciphertext = x25519_dalek::PublicKey;
    type SharedSecret = x25519_dalek::SharedSecret;

    fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let ek = x25519_dalek::PublicKey::from(&dk);
        (dk, ek)
    }

    fn encap(
        rng: &mut impl CryptoRngCore,
        ek: &Self::EncapsulationKey,
    ) -> (Self::Ciphertext, Self::SharedSecret) {
        let sk_e = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        let ct = x25519_dalek::PublicKey::from(&sk_e);
        let ss = sk_e.diffie_hellman(&ek);
        (ct, ss)
    }

    fn decap(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Self::SharedSecret {
        dk.diffie_hellman(&ct)
    }
}

// ML-KEM-768
pub type MlKemDecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;

#[derive(Clone)]
pub struct MlKemEncapsulationKey {
    ek: <MlKem768 as KemCore>::EncapsulationKey,
    ek_bytes: Encoded<<MlKem768 as KemCore>::EncapsulationKey>,
}

impl MlKemEncapsulationKey {
    fn new(ek: <MlKem768 as KemCore>::EncapsulationKey) -> Self {
        let ek_bytes = ek.as_bytes();
        Self { ek, ek_bytes }
    }
}

impl AsRef<[u8]> for MlKemEncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        self.ek_bytes.as_slice()
    }
}

pub struct MlKem;

impl BaseKem for MlKem {
    type DecapsulationKey = MlKemDecapsulationKey;
    type EncapsulationKey = MlKemEncapsulationKey;
    type Ciphertext = Array<u8, U1088>;
    type SharedSecret = Array<u8, U32>;

    fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (dk, ek) = MlKem768::generate(&mut *rng);
        (dk, MlKemEncapsulationKey::new(ek))
    }

    fn encap(
        rng: &mut impl CryptoRngCore,
        ek: &Self::EncapsulationKey,
    ) -> (Self::Ciphertext, Self::SharedSecret) {
        ek.ek.encapsulate(rng).unwrap()
    }

    fn decap(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Self::SharedSecret {
        dk.decapsulate(&ct).unwrap()
    }
}

// Classic McEliece
pub type McElieceDecapsulationKey = classic_mceliece_rust::SecretKey<'static>;

pub struct McElieceEncapsulationKey(classic_mceliece_rust::PublicKey<'static>);

impl Clone for McElieceEncapsulationKey {
    fn clone(&self) -> Self {
        Self(self.0.to_owned())
    }
}

impl AsRef<[u8]> for McElieceEncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct ClassicMcEliece;

impl BaseKem for ClassicMcEliece {
    type DecapsulationKey = McElieceDecapsulationKey;
    type EncapsulationKey = McElieceEncapsulationKey;
    type Ciphertext = classic_mceliece_rust::Ciphertext;
    type SharedSecret = classic_mceliece_rust::SharedSecret<'static>;

    fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (ek, dk) = classic_mceliece_rust::keypair_boxed(rng);
        (dk, McElieceEncapsulationKey(ek))
    }

    fn encap(
        rng: &mut impl CryptoRngCore,
        ek: &Self::EncapsulationKey,
    ) -> (Self::Ciphertext, Self::SharedSecret) {
        classic_mceliece_rust::encapsulate_boxed(&ek.0, rng)
    }

    fn decap(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Self::SharedSecret {
        classic_mceliece_rust::decapsulate_boxed(&ct, &dk)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_encap_decap<K: BaseKem>() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = K::generate(&mut rng);
        let (ct, ss_e) = K::encap(&mut rng, &ek);
        let ss_d = K::decap(&dk, &ct);
        assert_eq!(ss_e.as_ref(), ss_d.as_ref());
    }

    #[test]
    fn x25519() {
        test_encap_decap::<X25519>();
    }

    #[test]
    fn ml_kem() {
        test_encap_decap::<MlKem>();
    }

    #[test]
    fn classic_mceliece() {
        test_encap_decap::<ClassicMcEliece>();
    }
}
