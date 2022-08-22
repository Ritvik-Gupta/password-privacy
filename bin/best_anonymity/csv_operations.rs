use password_privacy::HashingDigest;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Deserialize)]
pub struct PasswordEntry {
    pub password: String,
}

pub fn read_from_csv(path_to_file: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut reader = csv::Reader::from_path(path_to_file)?;
    let mut records = Vec::new();

    for res in reader.deserialize() {
        let entry: PasswordEntry = res?;
        records.push(entry.password);
    }

    Ok(records)
}

#[derive(Serialize)]
pub struct HashAnonymityEntry {
    pub first_bits: usize,
    pub digest: HashingDigest,
    pub k_anonymity_achieved: usize,
    pub anonymity_imapct: usize,
}

pub fn write_to_csv(
    path_to_file: &str,
    records: Vec<HashAnonymityEntry>,
) -> Result<(), Box<dyn Error>> {
    let mut writer = csv::Writer::from_path(path_to_file)?;

    for record in records.iter() {
        writer.serialize(record)?;
    }

    Ok(())
}
