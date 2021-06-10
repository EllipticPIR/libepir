use criterion::{criterion_group, criterion_main, Criterion};

use epir::ecelgamal::*;

fn bench_encrypt(c: &mut Criterion) {
    let privkey = PrivateKey::new();
    let pubkey = PublicKey::new(&privkey);
    let enc_ctx = EncryptionContext::new();
    c.bench_function("encrypt_normal", |b| {
        b.iter(|| {
            pubkey.encrypt(&enc_ctx, &1234u32.into(), None);
        })
    });
    c.bench_function("encrypt_fast", |b| {
        b.iter(|| {
            privkey.encrypt(&enc_ctx, &1234u32.into(), None);
        })
    });
}

fn bench_load_mg(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_mg");
    group.sample_size(10);
    group.bench_function("load_mg", |b| {
        b.iter(|| {
            DecryptionContext::load_from_file(None).unwrap();
        })
    });
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let privkey = PrivateKey::new();
    let enc_ctx = EncryptionContext::new();
    let cipher = privkey.encrypt(&enc_ctx, &1234u32.into(), None);
    let dec_ctx = DecryptionContext::load_from_file(None).unwrap();
    c.bench_function("decrypt", |b| {
        b.iter(|| {
            dec_ctx.decrypt_cipher(&privkey, &cipher).unwrap();
        })
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_load_mg);
criterion_main!(benches);
