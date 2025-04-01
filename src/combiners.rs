use sha3::{digest::Output, Digest, Sha3_256};

use crate::{Combiner, SharedSecret};

pub trait NewPre {
    fn new_pre(ek_t: &[u8], ek_pq: &[u8]) -> Self;
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

impl NewPre for KitchenSinkPre {
    fn new_pre(ek_t: &[u8], ek_pq: &[u8]) -> Self {
        let mut prefix = Sha3_256::new();
        prefix.update(ek_t);
        prefix.update(ek_pq);
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

impl NewPre for ChempatPre {
    fn new_pre(ek_t: &[u8], ek_pq: &[u8]) -> Self {
        let mut h = Sha3_256::new();
        h.update(ek_t);
        h.update(ek_pq);

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

impl NewPre for DhkemPre {
    fn new_pre(ek_t: &[u8], ek_pq: &[u8]) -> Self {
        let mut prefix_t = Sha3_256::new();
        prefix_t.update(ek_t);

        let mut prefix_pq = Sha3_256::new();
        prefix_pq.update(ek_pq);

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
