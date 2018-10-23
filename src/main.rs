extern crate rustcoin;
use rustcoin::*;

extern crate digest;
extern crate sha2;

use std::fs::File;
use std::io::{BufRead, BufReader};

#[macro_use]
extern crate hex_literal;
extern crate hex;

fn main()
{
    let f = File::open("english.txt").expect("file not found");
    let reader = BufReader::new(f);

    let lines = reader.lines()
        .map(|el| el.unwrap())
        .collect::<Vec<_>>();

    println!("{}", generate_mnemonic::<MnemonicSize24w>(&lines));
    
    

/*
    let licorne = "cake apple borrow silk endorse fitness top denial coil riot stay wolf luggage oxygen faint major edit measure invite love trap field dilemma oblige";
    let mut slice = vec![0; <Sha512 as FixedOutput>::OutputSize::to_usize()];

    pbkdf2::<Hmac<Sha512>>(licorne.as_bytes(), "mnemonic".as_bytes(), 2048, &mut slice);

    let mut s = String::new();
    slice.write_hex(&mut s).unwrap();
    println!("Seed:\t{}", s);*/
}
