use criterion::{criterion_group, criterion_main, Criterion};

use epir::ecelgamal::*;

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

fn bench_encrypt(c: &mut Criterion) {
    let privkey = PrivateKey::new();
    let pubkey = PublicKey::new(&privkey);
    c.bench_function("encrypt_normal", |b| {
        b.iter(|| {
            pubkey.encrypt(&1234u32.into(), None);
        })
    });
    c.bench_function("encrypt_fast", |b| {
        b.iter(|| {
            privkey.encrypt(&1234u32.into(), None);
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let privkey = PrivateKey::new();
    let cipher = privkey.encrypt(&1234u32.into(), None);
    let dec_ctx = DecryptionContext::load_from_file(None).unwrap();
    c.bench_function("decrypt", |b| {
        b.iter(|| {
            dec_ctx.decrypt_cipher(&privkey, &cipher).unwrap();
        })
    });
}

const MMAX_MOD: u8 = 16;
const MMAX: u32 = 1 << MMAX_MOD;

fn bench_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate");
    let mut mgs = Vec::new();
    group.sample_size(10);
    group.bench_function("no_sort", |b| {
        b.iter(|| {
            mgs = DecryptionContext::generate_no_sort(Some(MMAX), |_| {});
        })
    });
    group.sample_size(100);
    group.bench_function("sort", |b| {
        b.iter(|| {
            DecryptionContext::generate_sort(&mut mgs);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_load_mg, bench_encrypt, bench_decrypt, bench_generate);
criterion_main!(benches);
