use clap::Parser;
use colored::*;
use csv_operations::*;
use password_privacy::{HashAnonymity, HashingDigest, DIGESTS};
use std::error::Error;

mod csv_operations;

const MAX_BIT_ANONYMITY: usize = 10;
const MAX_BIT_ANONYMITY_I64: i64 = MAX_BIT_ANONYMITY as i64;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    path_to_file: String,

    #[clap(short = 'b', long, value_parser = 1..=MAX_BIT_ANONYMITY_I64)]
    first_bits: Option<i64>,

    #[clap(short = 'd', long, value_enum)]
    for_digest: Option<HashingDigest>,

    #[clap(long, value_parser, default_value_t = false)]
    debug: bool,
}

fn compute_for_digest<'a>(
    hash_anonymity: &HashAnonymity,
    digest: HashingDigest,
    passwords: impl Iterator<Item = &'a str>,
    debug: bool,
) -> usize {
    let pswd_hash_records = digest.compute_on(hash_anonymity, passwords);

    if debug {
        println!("\n{}", "Password Hash Records :".bright_green());
        pswd_hash_records.iter().for_each(|(hash_bits, freq)| {
            println!("\t'{}' -> {}", hash_bits.bright_blue().bold(), freq);
        });
        println!();
    }

    *pswd_hash_records.values().min().unwrap_or(&0)
}

fn compare_and_find_best_digest(
    hash_anonymity: &HashAnonymity,
    passwords: Vec<String>,
) -> Vec<(HashingDigest, usize)> {
    DIGESTS
        .iter()
        .map(|&digest| {
            (
                digest,
                compute_for_digest(
                    hash_anonymity,
                    digest,
                    passwords.iter().map(|s| s.as_str()),
                    false,
                ),
            )
        })
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let passwords = read_from_csv(&args.path_to_file)?;

    match (args.first_bits.map(|x| x as usize), args.for_digest) {
        (Some(first_bits), Some(digest)) => {
            let hash_anonymity = HashAnonymity::for_first_bits(first_bits);
            let k_anonymity_achieved = compute_for_digest(
                &hash_anonymity,
                digest,
                passwords.iter().map(|s| s.as_str()),
                args.debug,
            );

            println!(
                "K-Anonymity achieved: {}",
                k_anonymity_achieved.to_string().bright_green().bold()
            );
        }
        (Some(first_bits), None) => {
            let hash_anonymity = HashAnonymity::for_first_bits(first_bits);

            let digest_performances = compare_and_find_best_digest(&hash_anonymity, passwords);

            digest_performances
                .iter()
                .for_each(|(digest, k_anonymity_achieved)| {
                    println!(
                        "Digest {} achieved {}-anonymity",
                        format!("{:?}", digest).bright_magenta(),
                        k_anonymity_achieved.to_string().bright_green().bold()
                    );
                });

            let &(best_digest, k_anonymity_achieved) =
                digest_performances.iter().max_by_key(|&(_, k)| k).unwrap();

            println!(
                "Best K-Anonymity achieved: {} for Digest {}",
                k_anonymity_achieved.to_string().bright_green().bold(),
                format!("{:?}", best_digest).bright_magenta(),
            );
        }
        (_, Some(digest)) => {
            let bit_performances: Vec<_> = (1..=MAX_BIT_ANONYMITY)
                .map(|first_bits| {
                    compute_for_digest(
                        &HashAnonymity::for_first_bits(first_bits),
                        digest,
                        passwords.iter().map(|s| s.as_str()),
                        false,
                    )
                })
                .collect();

            bit_performances.iter().enumerate().for_each(
                |(num_first_bits, k_anonymity_achieved)| {
                    println!(
                        "First {} Hash bits achieved {}-anonymity",
                        (num_first_bits + 1).to_string().bright_magenta(),
                        k_anonymity_achieved.to_string().bright_green().bold()
                    );
                },
            );

            let avg_k_anonymity = {
                let considered_anonymities = bit_performances
                    .iter()
                    .take_while(|&&k_anonymity| k_anonymity > 1)
                    .enumerate();

                considered_anonymities
                    .clone()
                    .map(|(num_first_bits, &k_anonymity)| num_first_bits * k_anonymity)
                    .sum::<usize>()
                    / considered_anonymities
                        .map(|(num_first_bits, _)| num_first_bits)
                        .sum::<usize>()
            };

            println!(
                "Average K-anonymity achieved: {} for Digest {}",
                avg_k_anonymity.to_string().bright_green().bold(),
                format!("{:?}", digest).bright_magenta(),
            );
        }
        _ => {
            let records: Vec<_> = (1..=MAX_BIT_ANONYMITY)
                .flat_map(|first_bits| {
                    compare_and_find_best_digest(
                        &HashAnonymity::for_first_bits(first_bits),
                        passwords.clone(),
                    )
                    .into_iter()
                    .map(move |(digest, k_anonymity_achieved)| HashAnonymityEntry {
                        first_bits,
                        digest,
                        k_anonymity_achieved,
                        anonymity_imapct: (first_bits - 1) * k_anonymity_achieved,
                    })
                })
                .collect();

            write_to_csv("./datasets/anonymities.csv", records)?;
        }
    }

    Ok(())
}
