use clap::Parser;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::SystemTime;
type HmacSha1 = Hmac<Sha1>;
use totp_rs::{Algorithm, Secret, TOTP};

/// A simple time-based one-time password generator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// The issuer of the key
    issuer: Option<String>,
}

fn main() {
    let args = Config::parse();
    // Generate hmac-sha-1 for key and timestep
    let secret = args.issuer.unwrap();
    let mut mac = HmacSha1::new_from_slice(&secret.as_bytes()).unwrap();

    let unix_time_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let time_steps = unix_time_secs / 30;
    mac.update(&time_steps.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // dynamic truncation
    let offset = (result.last().unwrap() & 15) as usize;
    let bin_code = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    let totp = format!("{1:00$}", 6, bin_code % 10_u32.pow(6));
    dbg!(totp);

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(secret.as_bytes().to_vec()).to_bytes().unwrap(),
    )
    .unwrap();
    let token = totp.generate_current().unwrap();
    println!("{}", token);
}
