extern crate rustcoin;
use rustcoin::{SecretKey, PublicKey, Address, ToBase58Check};

extern crate digest;
extern crate sha2;
use digest::{Digest, FixedOutput};
use sha2::{Sha256, Sha512};

use std::fs::File;
use std::io::{BufRead, BufReader};

#[macro_use]
extern crate hex_literal;
extern crate hex;
use hex::ToHex;
extern crate rand;

use rand::{thread_rng, Rng};

//entropy + checksum = total = 11 * words
//128 + 4 = 132 bits = 11 * 12 words
//160 + 5 = 165 bits = 11 * 15 words
//192 + 6 = 198 bits = 11 * 18 words
//224 + 7 = 231 bits = 11 * 21 words
//256 + 8 = 256 bits = 11 * 24 words
const MNEMONIC_CODES: (usize, usize) = (128, 4);

fn main()
{
    //generate entropy
    let mut rng = thread_rng();
    let mut array = [0; MNEMONIC_CODES.0/8 + 1]; 
    rng.fill(&mut array[..MNEMONIC_CODES.0/8]);

    array = hex!("9ba35336a766db2a5aa02c2154a7fb1900");

    let mut s = String::new();
    (&array[..]).write_hex(&mut s).unwrap();
    println!("Entropy:\t{}", s);

    //add checksum
    let checksum = Sha256::digest(&array[..MNEMONIC_CODES.0/8]);
    array[MNEMONIC_CODES.0/8] = checksum[0] & ((1 << MNEMONIC_CODES.1) - 1) << 8 - MNEMONIC_CODES.1;

    let mut s = String::new();
    checksum.write_hex(&mut s).unwrap();
    println!("Checksum:\t{}", s);

    let mut s = String::new();
    (&array[..]).write_hex(&mut s).unwrap();
    println!("Entropy:\t{}", s);

    //split into 11bits segments
    let mut segments = [0u16; (MNEMONIC_CODES.0 + MNEMONIC_CODES.1) / 11];
    let mut r = 8;
    let mut j = 0;
    for i in 0..(MNEMONIC_CODES.0 + MNEMONIC_CODES.1) / 11 {
        let al = 11 - r;
        let be = 8 - al;
        if be < 0 {
            let de = 8 + be;
            segments[i] = ((array[j] as u16) << al
                | (array[j + 1] as u16) << -be
                | (array[j + 2] >> de) as u16) & 0b11111111111;
            j += 2;
            r = de;
        }
        else {
            segments[i] = ((array[j] as u16) << al
                | (array[j + 1] >> be) as u16) & 0b11111111111;
            j += 1;
            r = be;
        }
    }

    println!("segments:\t{:?}", segments);

    //map with dictionnary
    let f = File::open("english.txt").expect("file not found");
    let reader = BufReader::new(f);

    let lines = reader.lines()
        .map(|el| el.unwrap())
        .collect::<Vec<_>>();
    let words = segments[..].iter()
        .map(|el| &lines[*el as usize])
        .map(|el| el.as_str())
        .collect::<Vec<_>>()
        .join(" ");

    println!("{:?}", words);
    
    

/*
    let licorne = "cake apple borrow silk endorse fitness top denial coil riot stay wolf luggage oxygen faint major edit measure invite love trap field dilemma oblige";
    let mut slice = vec![0; <Sha512 as FixedOutput>::OutputSize::to_usize()];

    pbkdf2::<Hmac<Sha512>>(licorne.as_bytes(), "mnemonic".as_bytes(), 2048, &mut slice);

    let mut s = String::new();
    slice.write_hex(&mut s).unwrap();
    println!("Seed:\t{}", s);*/
}
