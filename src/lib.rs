extern crate secp256k1;
#[macro_use]
extern crate hex_literal;
#[macro_use]
extern crate lazy_static;
extern crate generic_array;
extern crate digest;
extern crate sha2;
extern crate ripemd160;
extern crate base58;

use digest::{Digest, FixedOutput};
use sha2::{Sha256, Sha512};
use ripemd160::Ripemd160;
use generic_array::{
    GenericArray,
    sequence::Split, 
    typenum::{U4, Unsigned}
};
use base58::ToBase58;

lazy_static! {
    static ref SECP256K1_ENGINE: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}

#[derive(Debug)]
pub enum BitError
{
    Secp256k1(secp256k1::Error)
}

pub type Result<T> = std::result::Result<T, BitError>;

pub struct SecretKey(secp256k1::key::SecretKey);

impl SecretKey {
    pub const UNCOMPRESSED_SIZE: usize = secp256k1::constants::SECRET_KEY_SIZE;
    pub const COMPRESSED_SIZE: usize = SecretKey::UNCOMPRESSED_SIZE + 1;

    pub fn from_slice<T: AsRef<[u8]>>(bytes: T) -> Result<SecretKey>
    {
        match secp256k1::key::SecretKey::from_slice(&SECP256K1_ENGINE, bytes.as_ref()) {
            Ok(key) => Ok(SecretKey(key)),
            Err(err) => Err(BitError::Secp256k1(err))
        }
    }

    pub fn bytes_uncompressed(&self) -> Vec<u8>
    {
        Vec::from(&self.0[..])
    }

    pub fn bytes_compressed(&self) -> Vec<u8>
    {
        let mut vec = Vec::with_capacity(SecretKey::COMPRESSED_SIZE);
        vec.extend(&self.0[..]);
        vec.push(0x01);
        vec
    }
}

pub struct PublicKey(secp256k1::key::PublicKey);

impl PublicKey
{
    pub const UNCOMPRESSED_SIZE: usize = secp256k1::constants::SECRET_KEY_SIZE;
    pub const COMPRESSED_SIZE: usize = SecretKey::UNCOMPRESSED_SIZE + 1;

    pub fn from_secret_key(secret_key: &SecretKey) -> Result<PublicKey>
    {
        match secp256k1::key::PublicKey::from_secret_key(&SECP256K1_ENGINE, &secret_key.0) {
            Ok(key) => Ok(PublicKey(key)),
            Err(err) => Err(BitError::Secp256k1(err))
        }
    }

    pub fn bytes_uncompressed(&self) -> Vec<u8>
    {
        Vec::from(self.0.serialize_vec(&SECP256K1_ENGINE, false).as_slice())
    }

    pub fn bytes_compressed(&self) -> Vec<u8>
    {
        Vec::from(self.0.serialize_vec(&SECP256K1_ENGINE, true).as_slice())
    }
}

pub struct Address(Vec<u8>);

impl Address
{
    pub fn from_public_key(public_key: &PublicKey, compressed: bool) -> Address
    {
        let k = if compressed { public_key.bytes_compressed() } else { public_key.bytes_uncompressed() };
        Address(Vec::from(Ripemd160::digest(&Sha256::digest(&k)).as_slice()))
    }
}

impl AsRef<[u8]> for Address
{
    fn as_ref(&self) -> &[u8]
    {
        &self.0
    }
}

pub trait ToBase58Check
{
    fn to_base58_check(&self, prefix: u8) -> String;
}

impl<T: AsRef<[u8]>> ToBase58Check for T
{
    fn to_base58_check(&self, prefix: u8) -> String
    {
        //Add version prefix
        let mut result = vec![prefix];
        result.extend(self.as_ref());

        //checksum = Sha256(Sha256(prefix+digest))
        let checksum_digest = Sha256::digest(&Sha256::digest(&result));

        //use only first 4 bytes
        let (checksum, _): (GenericArray<u8, U4>, _) = checksum_digest.split();

        //concat & base58
        result.extend(checksum);
        result.to_base58()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn uncompressed_secret_key()
    {
        let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
        let test: &[u8] = &hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6");
        assert_eq!(secret_key.bytes_uncompressed(), test);
    }

    #[test]
    fn compressed_secret_key()
    {
        let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
        let test: &[u8] = &hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa601");
        assert_eq!(secret_key.bytes_compressed(), test);
    }

    #[test]
    fn wif_uncompressed_secret_key()
    {
        let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
        assert_eq!(secret_key.bytes_uncompressed().to_base58_check(0x80), "5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K");
    }

    #[test]
    fn wif_compressed_secret_key()
    {
        let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
        assert_eq!(secret_key.bytes_compressed().to_base58_check(0x80), "KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S");
    }

    #[test]
    fn uncompressed_public_key()
    {
        let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key).unwrap();
        let test: &[u8] = &hex!("045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176");
        assert_eq!(public_key.bytes_uncompressed(), test);
    }

    #[test]
    fn compressed_public_key()
    {
        let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key).unwrap();
        let test: &[u8] = &hex!("025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec");
        assert_eq!(public_key.bytes_compressed(), test);
    }

    #[test]
    fn uncompressed_address()
    {
        let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key).unwrap();
        let address = Address::from_public_key(&public_key, false);
        assert_eq!(address.to_base58_check(0x00), "1thMirt546nngXqyPEz532S8fLwbozud8");
    }

    #[test]
    fn compressed_address()
    {
        let secret_key = SecretKey::from_slice(&hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key).unwrap();
        let address = Address::from_public_key(&public_key, true);
        assert_eq!(address.to_base58_check(0x00), "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3");
    }
}
