use rucola::hash::SHA;
mod common;

#[test]
fn streaming_api_test() {
    let tv = common::parse_hash_vectors(&["./tests/tv/SHA256LongMsg.rsp",
                                        "./tests/tv/SHA256ShortMsg.rsp"]);
    let mut s2 = SHA::new_sha2();
    let mut out: [u8; 32] = [0; 32];

    for t in tv {
        out.fill(0);
        s2.init();
        s2.update(&t.0);
        s2.finish(&mut out);
        println!("expected: {:x?}", t.1);
        assert_eq!(t.1, out);
    }
}
