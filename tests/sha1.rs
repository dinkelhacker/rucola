use rucola::hash::SHA;

#[test]
fn streaming_api_test() {
    let tv = utilities::testutils::parse_hash_vectors(&["./tests/tv/SHA1LongMsg.rsp",
                                        "./tests/tv/SHA1ShortMsg.rsp"]);
    utilities::testutils::streaming_api_test::<20, SHA>(tv, &mut SHA::new_sha1());
}