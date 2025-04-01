use criterion::{criterion_group, criterion_main, Criterion};
use kem_combiners::*;

fn bench_combiner<C: Combiner>(
    c: &mut Criterion,
    combo: &C,
    dk: &DecapsulationKey,
    ek: &EncapsulationKey,
    label: &str,
) {
    let mut rng = rand::thread_rng();
    let (ct, ss) = kem_combiners::encap(combo, &mut rng, &ek);

    let ss_t = ss.as_slice();
    let ct_t = ct.t.as_bytes().as_slice();
    let ek_t = ek.t.as_bytes().as_slice();
    let ss_pq = ss.as_slice();
    let ct_pq = ct.pq.as_slice();
    let ek_pq = ek.pq_bytes.as_slice();

    c.bench_function(&format!("{}_raw", label), |b| {
        b.iter(|| {
            combo.combine(ss_t, ct_t, ek_t, ss_pq, ct_pq, ek_pq);
        })
    });

    c.bench_function(&format!("{}_encap", label), |b| {
        b.iter(|| {
            kem_combiners::encap(combo, &mut rng, &ek);
        })
    });

    c.bench_function(&format!("{}_decap", label), |b| {
        b.iter(|| {
            kem_combiners::decap(combo, &dk, &ct);
        })
    });
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let (dk, ek) = kem_combiners::generate(&mut rng);

    // Stateless
    bench_combiner(c, &KitchenSink, &dk, &ek, "kitchen_sink");
    bench_combiner(c, &Chempat, &dk, &ek, "chempat");
    bench_combiner(c, &Dhkem, &dk, &ek, "dhkem");
    bench_combiner(c, &DhkemHalf, &dk, &ek, "dhkem_half");
    bench_combiner(c, &XWing, &dk, &ek, "xwing");

    // Stateful
    let kitchen_sink_pre = KitchenSinkPre::new(&ek);
    bench_combiner(c, &kitchen_sink_pre, &dk, &ek, "kitchen_sink_pre");

    let chempat_pre = ChempatPre::new(&ek);
    bench_combiner(c, &chempat_pre, &dk, &ek, "chempat_pre");

    let dhkem_pre = DhkemPre::new(&ek);
    bench_combiner(c, &dhkem_pre, &dk, &ek, "dhkem_pre");
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
