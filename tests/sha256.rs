use std::fs::File;
use std::io::{self, BufRead, Lines, BufReader};
use std::path::Path;
use rucola::hash::SHA;
use regex::Regex;
use hex::FromHex;

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn parse_vectors() -> Vec<(Vec<u8>, Vec<u8>)>{
    let re_line = Regex::new(r"^Msg = (?P<msg>.*)$").unwrap();
    let re_digest = Regex::new(r"^MD = (?P<md>.*)$").unwrap();
    let mut vec:Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    if let Ok(lines) = read_lines("./tests/tv/SHA256LongMsg.rsp") {
        let mut m = Vec::<u8>::new();
        let mut state = 0;
    
        for line in lines {
            if let(Ok(l)) = line {
                match state {
                   0 => {
                       let cap = re_line.captures(&l);
                       if let Some(v) = cap {
                           m = hex::decode(v["msg"].to_string()).expect("Failed");
                           state = 1;
                       }
                   }, 
                   _ => {
                       let cap = re_digest.captures(&l);
                       if let Some(v) = cap {
                           let d = hex::decode(v["md"].to_string()).expect("Failed");
                           state = 0;
                           vec.push((m.to_owned(), d.to_owned()));
                       }
                   }

               }
           }
        }
    } else { println!("not found")}
    return vec;
}



#[test]
fn streaming_api_test() {
    let tv = parse_vectors();
    let mut s2 = SHA::new_sha2();
    let mut out: [u8; 32] = [0; 32];

    for t in tv {
        out.fill(0);
        s2.init();
        s2.update(&t.0);
        s2.finish(&mut out);
        println!("test");
        assert_eq!(t.1, out);
    }
}
