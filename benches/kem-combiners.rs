use criterion::{criterion_group, criterion_main, Criterion};
use kem_combiners::*;

fn bench_combiner<C: Combiner>(c: &mut Criterion, label: &str) {
    let mut rng = rand::thread_rng();
    let (dk, ek) = kem_combiners::generate(&mut rng);
    let (ct, ss) = kem_combiners::encap::<KitchenSink>(&mut rng, &ek);

    let ss_t = ss.as_slice();
    let ct_t = ct.t.as_bytes().as_slice();
    let ek_t = ek.t.as_bytes().as_slice();
    let ss_pq = ss.as_slice();
    let ct_pq = ct.pq.as_slice();
    let ek_pq = ek.pq_bytes.as_slice();

    c.bench_function(&format!("{}_raw", label), |b| {
        b.iter(|| {
            C::combine(ss_t, ct_t, ek_t, ss_pq, ct_pq, ek_pq);
        })
    });

    c.bench_function(&format!("{}_encap", label), |b| {
        b.iter(|| {
            kem_combiners::encap::<C>(&mut rng, &ek);
        })
    });

    c.bench_function(&format!("{}_decap", label), |b| {
        b.iter(|| {
            kem_combiners::decap::<C>(&dk, &ct);
        })
    });
}

pub fn criterion_benchmark(c: &mut Criterion) {
    bench_combiner::<KitchenSink>(c, "kitchen_sink");
    bench_combiner::<Chempat>(c, "chempat");
    bench_combiner::<Dhkem>(c, "dhkem");
    bench_combiner::<XWing>(c, "xwing");
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
