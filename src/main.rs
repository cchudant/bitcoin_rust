extern crate rustcoin;
use rustcoin::*;

use std::fs::File;
use std::io::{BufRead, BufReader};

fn main()
{
    let f = File::open("english.txt").expect("file not found");
    let reader = BufReader::new(f);

    let lines = reader.lines()
        .map(|el| el.unwrap())
        .collect::<Vec<_>>();

    println!("{}", generate_mnemonic::<MnemonicSize18w>(&lines));
}
