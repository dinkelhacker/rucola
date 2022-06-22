use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use rucola::hash::SHA;

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
#[test]
fn streaming_api_test() {

    if let Ok(lines) = read_lines("./tests/tv/SHA256LongMsg.rsp") {
        for line in lines {
                if let(Ok(l)) = line {
                    println!("{}",l);
                }
                break;
        }
    } else { println!("not found")}

    let mut input: [u8; 3] = [0x61, 0x62, 0x63];
    let mut s2 = SHA::new_sha2();
    let mut out: [u8; 32] = [0; 32];
    let expected = [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x1, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x3, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x0, 0x15, 0xad];
    
    s2.init();
    s2.update(&input);
    s2.finish(&mut out);
    assert_eq!(expected, out);
}
