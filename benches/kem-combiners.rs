use criterion::{criterion_group, criterion_main, Criterion};
use kem_combiners::{base::*, combiners::*, hybrid::*};

fn bench_combiner<T, PQ, C>(
    c: &mut Criterion,
    combo: &C,
    dk: &DecapsulationKey<T, PQ>,
    ek: &EncapsulationKey<T, PQ>,
    kem_label: &str,
    label: &str,
) where
    T: BaseKem,
    PQ: BaseKem,
    C: Combiner,
{
    let mut rng = rand::thread_rng();
    let (ct, ss) = HybridKem::encap(combo, &mut rng, &ek);

    let ss_t = ss.as_ref();
    let ct_t = ct.t.as_ref();
    let ek_t = ek.t.as_ref();
    let ss_pq = ss.as_ref();
    let ct_pq = ct.pq.as_ref();
    let ek_pq = ek.pq.as_ref();

    let raw_label = format!("{}_{}_raw", kem_label, label);
    c.bench_function(&raw_label, |b| {
        b.iter(|| {
            combo.combine(ss_t, ct_t, ek_t, ss_pq, ct_pq, ek_pq);
        })
    });

    let encap_label = format!("{}_{}_encap", kem_label, label);
    c.bench_function(&encap_label, |b| {
        b.iter(|| {
            HybridKem::encap(combo, &mut rng, &ek);
        })
    });

    let decap_label = format!("{}_{}_decap", kem_label, label);
    c.bench_function(&decap_label, |b| {
        b.iter(|| {
            HybridKem::decap(combo, &dk, &ct);
        })
    });
}

pub fn bench_hybrid<T, PQ>(c: &mut Criterion, kem: &str)
where
    T: BaseKem,
    PQ: BaseKem,
{
    let mut rng = rand::thread_rng();
    let (dk, ek) = HybridKem::<T, PQ>::generate(&mut rng);

    // Stateless
    bench_combiner(c, &KitchenSink, &dk, &ek, kem, "kitchen_sink");
    bench_combiner(c, &Chempat, &dk, &ek, kem, "chempat");
    bench_combiner(c, &Dhkem, &dk, &ek, kem, "dhkem");
    bench_combiner(c, &DhkemHalf, &dk, &ek, kem, "dhkem_half");
    bench_combiner(c, &XWing, &dk, &ek, kem, "xwing");

    // Stateful
    let kitchen_sink_pre = KitchenSinkPre::new_hybrid(&ek);
    bench_combiner(c, &kitchen_sink_pre, &dk, &ek, kem, "kitchen_sink_pre");

    let chempat_pre = ChempatPre::new_hybrid(&ek);
    bench_combiner(c, &chempat_pre, &dk, &ek, kem, "chempat_pre");

    let dhkem_pre = DhkemPre::new_hybrid(&ek);
    bench_combiner(c, &dhkem_pre, &dk, &ek, kem, "dhkem_pre");
}

pub fn criterion_benchmark(c: &mut Criterion) {
    bench_hybrid::<X25519, MlKem>(c, "x25510_ml_kem");
    bench_hybrid::<X25519, ClassicMcEliece>(c, "x25510_classic_mceliece");
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
