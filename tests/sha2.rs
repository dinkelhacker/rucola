use rucola::hash::SHA;
mod common;

#[test]
fn streaming_api_256() {
    let tv = common::parse_hash_vectors(&["./tests/tv/SHA256LongMsg.rsp",
                                        "./tests/tv/SHA256ShortMsg.rsp"]);
    common::streaming_api_test::<32, SHA>(tv, &mut SHA::new_sha256());
}

#[test]
fn streaming_api_224() {
    let tv = common::parse_hash_vectors(&["./tests/tv/SHA224LongMsg.rsp",
                                        "./tests/tv/SHA224ShortMsg.rsp"]);
    common::streaming_api_test::<28, SHA>(tv, &mut SHA::new_sha224());
}

#[test]
fn streaming_api_512() {
    let tv = common::parse_hash_vectors(&["./tests/tv/SHA512LongMsg.rsp",
                                        "./tests/tv/SHA512ShortMsg.rsp"]);
    common::streaming_api_test::<64, SHA>(tv, &mut SHA::new_sha512());
}


#[test]
fn streaming_api_384() {
    let tv = common::parse_hash_vectors(&["./tests/tv/SHA384LongMsg.rsp",
                                        "./tests/tv/SHA384ShortMsg.rsp"]);
    common::streaming_api_test::<48, SHA>(tv, &mut SHA::new_sha384());
}
