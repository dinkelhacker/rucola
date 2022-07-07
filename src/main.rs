//#![no_std]
use rucola::hash::SHA;

fn main() {
    let mut input: [u8; 3] = [0x61, 0x62, 0x63];
    let mut secinput: [u8; 70] = [1; 70];
    let mut s1 = SHA::new_sha1();
    let mut s2 = SHA::new_sha256();
    let mut s5 = SHA::new_sha512();
    let mut sha1 = Box::new(SHA::new_sha1());
    let mut out: [u8; 64] = [0; 64];

    s2.init();
    s2.update(&input);
    s2.finish(&mut out);
    println!("{:x?}", out);
    out.fill(0);
    s1.init();
    s1.update(&input);
    s1.finish(&mut out);
    println!("{:x?}", out);
    out.fill(0);
    s5.init();
    s5.update(&input);
    s5.finish(&mut out);
    println!("{:x?}", out);

    println!("{:?}", s1);
    println!("{:?}", s2);
    println!("{:?}", s5);
}
