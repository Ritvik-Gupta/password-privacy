use clap::Parser;
use colored::*;
use password_privacy::{HashAnonymity, HashingDigest, DIGESTS};
use serde::Deserialize;
use std::error::Error;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    path_to_file: String,

    #[clap(short = 'b', long, value_parser = 1..=10)]
    first_bits: Option<i64>,

    #[clap(short = 'd', long, value_enum)]
    for_digest: Option<HashingDigest>,

    #[clap(long, value_parser, default_value_t = false)]
    debug: bool,
}

#[derive(Deserialize)]
struct PasswordEntry {
    password: String,
}

fn read_from_csv(path_to_file: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut reader = csv::Reader::from_path(path_to_file)?;
    let mut records = Vec::new();

    for res in reader.deserialize() {
        let entry: PasswordEntry = res?;
        records.push(entry.password);
    }

    Ok(records)
}

fn compare_and_find_best_digest(
    hash_anonymity: HashAnonymity,
    passwords: Vec<String>,
) -> Vec<(HashingDigest, u32)> {
    DIGESTS
        .iter()
        .map(|&digest| {
            let pswd_hash_records =
                digest.compute_on(&hash_anonymity, passwords.iter().map(|s| s.as_str()));

            (digest, *pswd_hash_records.values().min().unwrap_or(&0))
        })
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let passwords = read_from_csv(&args.path_to_file)?;

    if let Some(digest) = args.for_digest {
        let hash_anonymity = HashAnonymity::for_first_bits(args.first_bits.unwrap() as usize);

        let pswd_hash_records =
            digest.compute_on(&hash_anonymity, passwords.iter().map(|s| s.as_str()));

        if args.debug {
            println!("\n{}", "Password Hash Records :".bright_green());
            pswd_hash_records.iter().for_each(|(hash_bits, freq)| {
                println!("\t'{}' -> {}", hash_bits.bright_blue().bold(), freq);
            });
            println!();
        }

        let k_anonymity_achieved = *pswd_hash_records.values().min().unwrap_or(&0);

        println!(
            "K-Anonymity achieved: {}",
            k_anonymity_achieved.to_string().bright_green().bold()
        );
    } else {
        let hash_anonymity = HashAnonymity::for_first_bits(args.first_bits.unwrap() as usize);

        let digest_performances = compare_and_find_best_digest(hash_anonymity, passwords);

        if args.debug {
            digest_performances
                .iter()
                .for_each(|(digest, k_anonymity_achieved)| {
                    println!(
                        "Digest {} achieved {}-anonymity",
                        format!("{:?}", digest).bright_magenta(),
                        k_anonymity_achieved.to_string().bright_green().bold()
                    );
                });
        }

        let &(best_digest, k_anonymity_achieved) =
            digest_performances.iter().max_by_key(|&(_, k)| k).unwrap();

        println!(
            "Best K-Anonymity achieved: {} for Digest {}",
            k_anonymity_achieved.to_string().bright_green().bold(),
            format!("{:?}", best_digest).bright_magenta(),
        );
    }

    Ok(())
}
