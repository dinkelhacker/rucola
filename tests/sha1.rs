use rucola::hash::SHA;
mod common;

#[test]
fn streaming_api_test() {
    let tv = common::parse_hash_vectors(&["./tests/tv/SHA1LongMsg.rsp",
                                        "./tests/tv/SHA1ShortMsg.rsp"]);
    common::streaming_api_test::<20, SHA>(tv, &mut SHA::new_sha1());
}
