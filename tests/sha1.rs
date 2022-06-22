use rucola::hash::SHA;
#[test]
fn streaming_api_test() {
    let input: [u8; 3] = [0x61, 0x62, 0x63];
    let mut s = SHA::new_sha1();
    let mut out: [u8; 20] = [0; 20];
    let expected = [0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D];
    
    s.init();
    s.update(&input);
    s.finish(&mut out);
    assert_eq!(expected, out);
}
