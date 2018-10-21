extern crate signatory;
extern crate signatory_secp256k1;
extern crate hex;
#[macro_use]
extern crate generic_array;
extern crate digest;
extern crate sha2;
extern crate ripemd160;
extern crate base58;

use signatory::{curve::secp256k1::SecretKey, PublicKeyed};
use signatory_secp256k1::EcdsaSigner;
use hex::{ToHex, FromHex};
use generic_array::{arr, GenericArray, sequence::Concat, sequence::Split, typenum::U4};
use digest::Digest;
use sha2::Sha256;
use ripemd160::Ripemd160;
use base58::ToBase58;

fn main() {

    // Secret Key

    let key = Vec::from_hex("038109007313a5807b2eccc082c8c3fbb988a973cacf1a7df9ce725c31b14776").unwrap();
    let secret_key = SecretKey::from_bytes(key).unwrap();

    let mut s = String::new();
    secret_key.as_secret_slice().write_hex(&mut s).unwrap();
    println!("Secret key:\t{}", s);

    // Public Key

    let signer = EcdsaSigner::from(&secret_key);
    let public_key = signer.public_key().unwrap();

    let mut s = String::new();
    public_key.write_hex(&mut s).unwrap();
    println!("Public key:\t{}", s);

    // Payload

    //HASH160
    let payload_digest = Ripemd160::digest(&Sha256::digest(&public_key.as_bytes()));

    //Add version prefix
    let payload = arr![u8; 0].concat(payload_digest);

    //checksum = Sha256(Sha256(prefix+digest))
    let checksum_digest = Sha256::digest(&Sha256::digest(&payload));

    //use only first 4 bytes
    let (checksum, _): (GenericArray<u8, U4>, _) = checksum_digest.split();

    //concat & base58
    let raw_address = payload.concat(checksum);
    let bitcoin_address = raw_address.to_base58();

    println!("Bitcoin addr:\t{}", bitcoin_address);

}
