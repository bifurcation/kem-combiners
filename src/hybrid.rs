use crate::base::BaseKem;
use crate::combiners::{Combiner, NewPre};

use rand_core::CryptoRngCore;
use sha3::{digest::Output, Sha3_256};

pub struct DecapsulationKey<T, PQ>
where
    T: BaseKem,
    PQ: BaseKem,
{
    pub t: T::DecapsulationKey,
    pub pq: PQ::DecapsulationKey,
    pub ek: EncapsulationKey<T, PQ>,
}

pub struct EncapsulationKey<T, PQ>
where
    T: BaseKem,
    PQ: BaseKem,
{
    pub t: T::EncapsulationKey,
    pub pq: PQ::EncapsulationKey,
}

// XXX(RLB) For some reason this has to be done manually.
impl<T, PQ> Clone for EncapsulationKey<T, PQ>
where
    T: BaseKem,
    PQ: BaseKem,
{
    fn clone(&self) -> Self {
        Self {
            t: self.t.clone(),
            pq: self.pq.clone(),
        }
    }
}

pub struct Ciphertext<T, PQ>
where
    T: BaseKem,
    PQ: BaseKem,
{
    pub t: T::Ciphertext,
    pub pq: PQ::Ciphertext,
}

pub type SharedSecret = Output<Sha3_256>;

pub trait NewHybrid<T, PQ>
where
    T: BaseKem,
    PQ: BaseKem,
{
    fn new_hybrid(ek: &EncapsulationKey<T, PQ>) -> Self;
}

impl<C, T, PQ> NewHybrid<T, PQ> for C
where
    C: NewPre,
    T: BaseKem,
    PQ: BaseKem,
{
    fn new_hybrid(ek: &EncapsulationKey<T, PQ>) -> Self {
        Self::new_pre(ek.t.as_ref(), ek.pq.as_ref())
    }
}

pub struct HybridKem<T, PQ>
where
    T: BaseKem,
    PQ: BaseKem,
{
    _phantom_t: std::marker::PhantomData<T>,
    _phantom_pq: std::marker::PhantomData<PQ>,
}

impl<T, PQ> HybridKem<T, PQ>
where
    T: BaseKem,
    PQ: BaseKem,
{
    pub fn generate(
        rng: &mut impl CryptoRngCore,
    ) -> (DecapsulationKey<T, PQ>, EncapsulationKey<T, PQ>) {
        let (dk_t, ek_t) = T::generate(rng);
        let (dk_pq, ek_pq) = PQ::generate(rng);

        let ek = EncapsulationKey { t: ek_t, pq: ek_pq };
        let dk = DecapsulationKey {
            t: dk_t,
            pq: dk_pq,
            ek: (&ek).clone(),
        };
        (dk, ek)
    }

    pub fn encap<C: Combiner>(
        c: &C,
        rng: &mut impl CryptoRngCore,
        ek: &EncapsulationKey<T, PQ>,
    ) -> (Ciphertext<T, PQ>, SharedSecret) {
        let (ct_t, ss_t) = T::encap(rng, &ek.t);
        let (ct_pq, ss_pq) = PQ::encap(rng, &ek.pq);

        let ct: Ciphertext<T, PQ> = Ciphertext { t: ct_t, pq: ct_pq };
        let ss = c.combine(
            ss_t.as_ref(),
            ct.t.as_ref(),
            ek.t.as_ref(),
            ss_pq.as_ref(),
            ct.pq.as_ref(),
            ek.pq.as_ref(),
        );
        (ct, ss)
    }

    pub fn decap<C: Combiner>(
        c: &C,
        dk: &DecapsulationKey<T, PQ>,
        ct: &Ciphertext<T, PQ>,
    ) -> SharedSecret {
        let ss_t = T::decap(&dk.t, &ct.t);
        let ss_pq = PQ::decap(&dk.pq, &ct.pq);

        c.combine(
            ss_t.as_ref(),
            ct.t.as_ref(),
            dk.ek.t.as_ref(),
            ss_pq.as_ref(),
            ct.pq.as_ref(),
            dk.ek.pq.as_ref(),
        )
    }
}
