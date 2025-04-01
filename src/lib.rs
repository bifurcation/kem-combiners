pub mod combiners;
pub mod ml_kem;

use sha3::{digest::Output, Sha3_256};

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

type SharedSecret = Output<Sha3_256>;
