use blake2::{Blake2b512, Blake2s256};
use fsb::{Fsb160, Fsb256, Fsb512};
use hex::ToHex;
use md2::Md2;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::collections::HashMap;
use whirlpool::Whirlpool;
use HashingDigest::*;

pub fn hash_password<D: Digest>(password: &str) -> String {
    let mut hasher = D::new();
    hasher.update(password);
    hasher.finalize().encode_hex()
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Serialize)]
pub enum HashingDigest {
    SHA1,
    SHA256,
    SHA512,
    SHA3_256,
    SHA3_512,
    BLAKE2S256,
    BLAKE2B512,
    FSB160,
    FSB256,
    FSB512,
    MD2,
    WHIRLPOOL,
}

pub static DIGESTS: &[HashingDigest] = &[
    SHA1, SHA256, SHA512, SHA3_256, SHA3_512, BLAKE2S256, BLAKE2B512, FSB160, FSB256, FSB512, MD2,
    WHIRLPOOL,
];

impl HashingDigest {
    pub fn compute_on<'a>(
        &self,
        hash_anonymity: &HashAnonymity,
        passwords: impl Iterator<Item = &'a str>,
    ) -> HashMap<String, usize> {
        match self {
            SHA1 => hash_anonymity.compute_for::<Sha1, _>(passwords),
            SHA256 => hash_anonymity.compute_for::<Sha256, _>(passwords),
            SHA512 => hash_anonymity.compute_for::<Sha512, _>(passwords),
            SHA3_256 => hash_anonymity.compute_for::<Sha3_256, _>(passwords),
            SHA3_512 => hash_anonymity.compute_for::<Sha3_512, _>(passwords),
            BLAKE2S256 => hash_anonymity.compute_for::<Blake2s256, _>(passwords),
            BLAKE2B512 => hash_anonymity.compute_for::<Blake2b512, _>(passwords),
            FSB160 => hash_anonymity.compute_for::<Fsb160, _>(passwords),
            FSB256 => hash_anonymity.compute_for::<Fsb256, _>(passwords),
            FSB512 => hash_anonymity.compute_for::<Fsb512, _>(passwords),
            MD2 => hash_anonymity.compute_for::<Md2, _>(passwords),
            WHIRLPOOL => hash_anonymity.compute_for::<Whirlpool, _>(passwords),
        }
    }
}

pub struct HashAnonymity {
    first_bits: usize,
}

impl HashAnonymity {
    pub fn for_first_bits(first_bits: usize) -> Self {
        Self { first_bits }
    }

    pub fn compute_for<'a, D: Digest, Itr: Iterator<Item = &'a str>>(
        &self,
        passwords: Itr,
    ) -> HashMap<String, usize> {
        let mut pswd_hash_records = HashMap::<String, usize>::new();

        passwords.for_each(|password| {
            let hash = hash_password::<D>(&password);

            *pswd_hash_records
                .entry(hash[0..self.first_bits].to_string())
                .or_insert(0) += 1;
        });

        pswd_hash_records
    }
}
