use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rucola::{hash, common::api::{DefaultInit, SingleInputUpdate, SingleOutputFinish}};
use utilities::testutils;


pub fn criterion_benchmark(c: &mut Criterion) {
    let tv = testutils::parse_hash_vectors(&["./tests/tv/SHA1LongMsg.rsp",
                                        /*"./tests/tv/SHA1ShortMsg.rsp"*/]);

    let mut sha1 = hash::SHA::new_sha1();
    let mut hash: [u8; 20] = [0;20];
    for t in tv {
        hash.fill(0);
        c.bench_function("sha1 bench long inputs".as_str(), |b| b.iter(|| testutils::single_test(black_box(&t.0), &mut sha1, &mut hash)));
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);