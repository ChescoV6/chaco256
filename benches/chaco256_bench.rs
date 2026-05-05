use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use chaco256::{Chaco256, Chaco256Aead, Key, Nonce, Rounds};

fn bench_stream_cipher(c: &mut Criterion) {
    let key = Key::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 24]);

    let mut group = c.benchmark_group("stream_cipher");

    // Benchmark different data sizes
    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(format!("{}_bytes", size), size, |b, &size| {
            let mut data = vec![0u8; size];
            b.iter(|| {
                let mut cipher = Chaco256::new(&key, &nonce);
                cipher.encrypt(black_box(&mut data));
            });
        });
    }

    group.finish();
}

fn bench_rounds(c: &mut Criterion) {
    let key = Key::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 24]);
    let mut data = vec![0u8; 4096];

    let mut group = c.benchmark_group("rounds");
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("light_16_rounds", |b| {
        b.iter(|| {
            let mut cipher = Chaco256::new_with_rounds(&key, &nonce, Rounds::Light);
            cipher.encrypt(black_box(&mut data));
        });
    });

    group.bench_function("standard_20_rounds", |b| {
        b.iter(|| {
            let mut cipher = Chaco256::new_with_rounds(&key, &nonce, Rounds::Standard);
            cipher.encrypt(black_box(&mut data));
        });
    });

    group.bench_function("paranoid_24_rounds", |b| {
        b.iter(|| {
            let mut cipher = Chaco256::new_with_rounds(&key, &nonce, Rounds::Paranoid);
            cipher.encrypt(black_box(&mut data));
        });
    });

    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let key = Key::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 24]);
    let aead = Chaco256Aead::new(&key);

    let mut group = c.benchmark_group("aead");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(format!("encrypt_{}_bytes", size), size, |b, &size| {
            let plaintext = vec![0u8; size];
            let ad = b"associated data";
            b.iter(|| {
                aead.encrypt(black_box(&nonce), black_box(&plaintext), black_box(ad));
            });
        });

        group.bench_with_input(format!("decrypt_{}_bytes", size), size, |b, &size| {
            let plaintext = vec![0u8; size];
            let ad = b"associated data";
            let (ciphertext, tag) = aead.encrypt(&nonce, &plaintext, ad);
            b.iter(|| {
                aead.decrypt(
                    black_box(&nonce),
                    black_box(&ciphertext),
                    black_box(&tag),
                    black_box(ad),
                )
                .unwrap();
            });
        });
    }

    group.finish();
}

fn bench_key_generation(c: &mut Criterion) {
    let key = Key::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 24]);

    c.bench_function("generate_single_block", |b| {
        b.iter(|| {
            Chaco256::generate_block(
                black_box(&key),
                black_box(&nonce),
                black_box(0),
                Rounds::Standard,
            );
        });
    });
}

criterion_group!(
    benches,
    bench_stream_cipher,
    bench_rounds,
    bench_aead,
    bench_key_generation
);
criterion_main!(benches);
