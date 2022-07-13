use std::fs::File;
use std::io::{self, BufRead, Lines, BufReader};
use std::path::Path;
use regex::Regex;
use hex::FromHex;
use rand::Rng;
use rucola::hash::SHA;
use rucola::common::api::{StreamingAPI, DefaultInit, SingleInputUpdate, SingleOutputFinish};

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn parse_hash_vectors(files: &[&'static str]) -> Vec<(Vec<u8>, Vec<u8>)>{
    let re_line = Regex::new(r"^Msg = (?P<msg>.*)$").unwrap();
    let re_digest = Regex::new(r"^MD = (?P<md>.*)$").unwrap();
    let mut vec:Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for file in files {
        if let Ok(lines) = read_lines(file) {
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
    }
    return vec;
}

pub fn streaming_api_test<const DS: usize, Prim>(tv: Vec<(Vec<u8>, Vec<u8>)>, s: &mut Prim)
    where Prim: StreamingAPI {
    let mut rng = rand::thread_rng();
    let mut out: [u8; DS] = [0; DS];
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