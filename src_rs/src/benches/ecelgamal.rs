use criterion::{criterion_group, criterion_main, Criterion};

use epir::ecelgamal::*;

fn bench_encrypt(c: &mut Criterion) {
    c.bench_function("encrypt_fast", |b| {
        let privkey = PrivateKey::new();
        let enc_ctx = EncryptionContext::new();
        b.iter(|| {
            privkey.encrypt(&enc_ctx, &1234u32.into(), None);
        })
    });
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
