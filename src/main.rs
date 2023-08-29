use clap::Parser;
use sotp::otp::Totp;
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
    let encoded = base32::encode(
        base32::Alphabet::RFC4648 { padding: false },
        args.issuer.clone().unwrap().as_bytes(),
    );
    let totp = Totp::new(args.issuer.unwrap());
    let other_totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(encoded).to_bytes().unwrap(),
    )
    .unwrap();
    //dbg!(&totp);
    dbg!(&totp.get());
    //dbg!(&other_totp);
    dbg!(&other_totp.generate_current().unwrap());
}
