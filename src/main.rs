extern crate secp256k1;
#[macro_use]
extern crate hex_literal;
extern crate hex;
extern crate generic_array;
extern crate digest;
extern crate sha2;
extern crate ripemd160;
extern crate base58;

/*use signatory::{curve::secp256k1::SecretKey, PublicKeyed};*/
use secp256k1::{
    Secp256k1,
    key::SecretKey,
    key::PublicKey
};
use hex::ToHex;
use generic_array::{
    GenericArray,
    sequence::Split, 
    typenum::U4
};
use digest::Digest;
use sha2::Sha256;
use ripemd160::Ripemd160;
use base58::ToBase58;

fn main()
{
    let engine = Secp256k1::new();

    // Secret Key

    let secret_key = SecretKey::from_slice(&engine, &hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
    let s_secret_key = secret_key[..].as_ref();

    let mut s = String::new();
    s_secret_key.write_hex(&mut s).unwrap();
    println!("Secret key:\t{}", s);

    println!("WIF Secret:\t{}", base58_check(0x80, s_secret_key));

    let mut cs_secret_key = Vec::from(s_secret_key);
    cs_secret_key.push(0x01);

    let mut s = String::new();
    cs_secret_key.write_hex(&mut s).unwrap();
    println!("CSecret key:\t{}", s);

    println!("WIF-c Secret:\t{}", base58_check(0x80, &cs_secret_key));

    // Public Key

    let public_key = PublicKey::from_secret_key(&engine, &secret_key).unwrap();
    let s_public_key = public_key.serialize_vec(&engine, false);
    let sc_public_key = public_key.serialize_vec(&engine, true);

    let mut s = String::new();
    s_public_key.write_hex(&mut s).unwrap();
    println!("Public key:\t{}", s);

    let mut s = String::new();
    sc_public_key.write_hex(&mut s).unwrap();
    println!("CPublic key:\t{}", s);

    // Payload

    println!("Bitcoin addr:\t{}", base58_check(0, &address(&s_public_key)));
    println!("CBitcoin addr:\t{}", base58_check(0, &address(&sc_public_key)));
}

fn address(public_key: &[u8]) -> Vec<u8>
{
    //HASH160
    Vec::from(Ripemd160::digest(&Sha256::digest(public_key)).as_slice())
}

fn base58_check(prefix: u8, payload: &[u8]) -> String
{
    //Add version prefix
    let mut result = vec![prefix];
    result.extend(payload);

    //checksum = Sha256(Sha256(prefix+digest))
    let checksum_digest = Sha256::digest(&Sha256::digest(&result));

    //use only first 4 bytes
    let (checksum, _): (GenericArray<u8, U4>, _) = checksum_digest.split();

    //concat & base58
    result.extend(checksum);
    result.to_base58()
}
