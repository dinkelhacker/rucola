use rucola::hash::SHA;
mod common;

#[test]
fn streaming_api_test() {
    let tv = common::parse_hash_vectors(&["./tests/tv/SHA256LongMsg.rsp",
                                        "./tests/tv/SHA256ShortMsg.rsp"]);
    common::streaming_api_test::<32>(tv, &mut SHA::new_sha2());
}
