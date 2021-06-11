use criterion::{criterion_group, criterion_main, Criterion};

use epir::*;
use epir::ecelgamal::*;
use epir::selector::*;

fn selector(c: &mut Criterion) {
    let mut group = c.benchmark_group("selector");
    group.sample_size(10);
    let mut rng: DefaultRng = Default::default();
    let privkey = PrivateKey::new(&mut rng);
    let pubkey = PublicKey::new(&privkey);
    let ic = IndexCount::new(&[1000, 1000, 1000]);
    group.bench_function("normal", |b| {
        b.iter(|| {
            Selector::create(&pubkey, &ic, 12345, &mut rng);
        })
    });
    group.bench_function("fast", |b| {
        b.iter(|| {
            Selector::create(&privkey, &ic, 12345, &mut rng);
        })
    });
}

criterion_group!(benches, selector);
criterion_main!(benches);
