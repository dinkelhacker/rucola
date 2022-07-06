use rucola::hash::SHA;
use rand::Rng;
mod common;

#[test]
fn streaming_api_test() {
    let tv = common::parse_hash_vectors(&["./tests/tv/SHA1LongMsg.rsp",
                                        "./tests/tv/SHA1ShortMsg.rsp"]);
    let mut rng = rand::thread_rng();
    let mut s = SHA::new_sha1();
    let mut out: [u8; 20] = [0; 20];
    for t in tv {
        out.fill(0);
        s.init();
        let mut n = 0;
        while n < t.0.len() {
            let mut r = rng.gen_range(0..t.0.len()+1);
            if r + n > t.0.len() {
                r = t.0.len() - n;
            }

            s.update(&t.0[n..n+r]);
            n += r;
        }
        s.finish(&mut out);
        println!("expected: {:x?}", t.1);
        assert_eq!(t.1, out);
    }
}
