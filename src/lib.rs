extern crate secp256k1;
#[macro_use]
extern crate lazy_static;
extern crate generic_array;
extern crate digest;
extern crate sha2;
extern crate ripemd160;
extern crate base58;
extern crate rand;
extern crate pbkdf2;
extern crate hmac;

use std::marker::PhantomData;
use digest::Digest;
use sha2::{Sha256, Sha512};
use ripemd160::Ripemd160;
use generic_array::{
    GenericArray,
    sequence::Split, 
    typenum::U4
};
use base58::ToBase58;
use rand::{thread_rng, Rng};
use pbkdf2::pbkdf2;
use hmac::Hmac;

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

pub trait MnemonicSize
{
    fn entropy_bytes() -> usize;
    fn entropy_bits() -> usize;
    fn checksum_bits() -> usize;
    fn checksum_mask() -> u8;
    fn total_bits() -> usize;
    fn total_bytes() -> usize;
    fn words() -> usize;
}

macro_rules! gen_mnemonic_size {
    ($name:ident, $bits:expr, $checksum:expr) => {
        pub struct $name;
        impl MnemonicSize for $name
        {
            fn entropy_bytes() -> usize { $bits/8 }
            fn entropy_bits() -> usize { $bits }
            fn checksum_bits() -> usize { $checksum }
            fn checksum_mask() -> u8 { (((1 << $checksum as u16) - 1) as u8) << 8 - $checksum }
            fn total_bits() -> usize { $bits + $checksum }
            fn total_bytes() -> usize { $bits / 8 + 1 }
            fn words() -> usize { ($bits + $checksum) / 11 }
        }
    };
}

//entropy + checksum = total = 11 * words
//128 + 4 = 132 bits = 11 * 12 words
//160 + 5 = 165 bits = 11 * 15 words
//192 + 6 = 198 bits = 11 * 18 words
//224 + 7 = 231 bits = 11 * 21 words
//256 + 8 = 256 bits = 11 * 24 words
gen_mnemonic_size!(MnemonicSize12w, 128, 4);
gen_mnemonic_size!(MnemonicSize15w, 160, 5);
gen_mnemonic_size!(MnemonicSize18w, 192, 6);
gen_mnemonic_size!(MnemonicSize21w, 224, 7);
gen_mnemonic_size!(MnemonicSize24w, 256, 8);

pub struct Mnemonic<S: MnemonicSize>(Vec<u8>, PhantomData<S>);

impl<S: MnemonicSize> Mnemonic<S>
{
    pub fn generate() -> Mnemonic<S>
    {
        let mut rng = thread_rng();
        let mut entropy = vec![0; S::entropy_bytes()]; 
        rng.fill(&mut entropy[..]);
        Mnemonic(entropy, PhantomData)
    }

    pub fn from_entropy(entropy: Vec<u8>) -> Mnemonic<S>
    {
        debug_assert_eq!(entropy.len(), S::entropy_bytes());
        Mnemonic(entropy, PhantomData)
    }

    pub fn words(self, dictionary: &[String]) -> String
    {
        let mut array = Vec::with_capacity(S::total_bytes());
        array.extend(self.0);
        array.push(0);

        //add checksum
        let checksum = Sha256::digest(&array[..S::entropy_bytes()]);
        array[S::entropy_bytes()] = checksum[0] & S::checksum_mask();

        //split into 11bits segments
        let mut segments = Vec::with_capacity(S::words());
        let mut r = 8;
        let mut j = 0;
        for _ in 0..S::words() {
            let al = 11 - r;
            let be = 8 - al;
            if be < 0 {
                let de = 8 + be;
                segments.push(
                    ((array[j] as u16) << al
                        | (array[j + 1] as u16) << -be
                        | (array[j + 2] >> de) as u16) & 0b11111111111
                );
                j += 2;
                r = de;
            }
            else {
                segments.push(
                    ((array[j] as u16) << al
                        | (array[j + 1] >> be) as u16) & 0b11111111111
                );
                j += 1;
                r = be;
            }
        }

        //map with dictionnary
        segments[..].iter()
            .map(|el| &dictionary[*el as usize])
            .map(|el| el.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub struct Seed(Vec<u8>);

impl Seed
{
    pub const SIZE: usize = 512 / 8; //512 bits

    pub fn from_words(words: &str, passphrase: &str) -> Seed
    {
        let mut vec = vec![0; Seed::SIZE];
        pbkdf2::<Hmac<Sha512>>(words.as_bytes(), ("mnemonic".to_owned() + passphrase).as_bytes(), 2048, &mut vec);
        Seed(vec)
    }
}

impl AsRef<[u8]> for Seed
{
    fn as_ref(&self) -> &[u8]
    {
        &self.0
    }
}

#[cfg(test)]
#[macro_use]
extern crate hex_literal;


#[cfg(test)]
mod tests
{
    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

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

    #[test]
    fn mnemonic_from_entropy()
    {
        let f = File::open("english.txt").expect("file not found");
        let reader = BufReader::new(f);

        let lines = reader.lines()
            .map(|el| el.unwrap())
            .collect::<Vec<_>>();

        let entropy: &[u8] = &hex!("0c1e24e5917779d297e14d45f14e1a1a");
        let mnemonic = Mnemonic::<MnemonicSize12w>::from_entropy(Vec::from(entropy));
        let test: &[u8] = &hex!("5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570");
        assert_eq!(Seed::from_words(mnemonic.words(&lines).as_str(), "").as_ref(), test);
    }

    #[test]
    fn mnemonic_seed()
    {
        let words = "army van defense carry jealous true garbage claim echo media make crunch";
        let test: &[u8] = &hex!("5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570");
        assert_eq!(Seed::from_words(words, "").as_ref(), test);
    }
}
