use rand_core::{OsRng, RngCore};
use criterion::{criterion_group, criterion_main, Criterion};

use epir::*;
use epir::ecelgamal::*;
use epir::reply::*;

fn reply(c: &mut Criterion) {
    const DIMENSION: u8    =  3;
    const PACKING  : u8    =  3;
    const ELEM_SIZE: usize = 32;
    let mut group = c.benchmark_group("reply");
    group.sample_size(10);
    let mut rng: DefaultRng = Default::default();
    let privkey = PrivateKey::new(&mut rng);
    let mut elem = [0u8; ELEM_SIZE];
    OsRng::default().fill_bytes(&mut elem);
    let reply = Reply::mock(&privkey, DIMENSION, PACKING, &elem, &mut rng);
    let dec_ctx = DecryptionContext::load_from_file(None).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            reply.decrypt(&dec_ctx, &privkey, DIMENSION, PACKING).unwrap();
        })
    });
}

criterion_group!(benches, reply);
criterion_main!(benches);
