extern crate hex;
#[macro_use]
extern crate hex_literal;

use hex::ToHex;

extern crate rustcoin;
use rustcoin::{SecretKey, PublicKey, Address, ToBase58Check};

fn main()
{
    // Secret Key

    let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
    let s_bytes = secret_key.bytes_uncompressed();
    let sc_bytes = secret_key.bytes_compressed();

    let mut s = String::new();
    s_bytes.write_hex(&mut s).unwrap();
    println!("Secret key:\t{}", s);

    println!("WIF Secret:\t{}", s_bytes.to_base58_check(0x80));

    let mut s = String::new();
    sc_bytes.write_hex(&mut s).unwrap();
    println!("cSecret key:\t{}", s);

    println!("cWIF Secret:\t{}", sc_bytes.to_base58_check(0x80));

    // Public Key

    let public_key = PublicKey::from_secret_key(&secret_key).unwrap();
    let p_bytes = public_key.bytes_uncompressed();
    let pc_bytes = public_key.bytes_compressed();

    let mut s = String::new();
    p_bytes.write_hex(&mut s).unwrap();
    println!("Public key:\t{}", s);

    let mut s = String::new();
    pc_bytes.write_hex(&mut s).unwrap();
    println!("cPublic key:\t{}", s);

    // Address

    let address = Address::from_public_key(&public_key, false);
    let caddress = Address::from_public_key(&public_key, true);

    println!("Address:\t{}", address.to_base58_check(0x00));
    println!("cAddress:\t{}", caddress.to_base58_check(0x00));

/*
    let licorne = "cake apple borrow silk endorse fitness top denial coil riot stay wolf luggage oxygen faint major edit measure invite love trap field dilemma oblige";
    let mut slice = vec![0; <Sha512 as FixedOutput>::OutputSize::to_usize()];

    pbkdf2::<Hmac<Sha512>>(licorne.as_bytes(), "mnemonic".as_bytes(), 2048, &mut slice);

    let mut s = String::new();
    slice.write_hex(&mut s).unwrap();
    println!("Seed:\t{}", s);*/
}
