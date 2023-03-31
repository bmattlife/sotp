use base32;
use clap::Parser;
use sotp::otp::Totp;

/// A simple time-based one-time password generator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// The issuer of the key
    issuer: Option<String>,
}

fn main() {
    let args = Config::parse();
    /*let encoded = base32::encode(
        base32::Alphabet::RFC4648 { padding: true },
        args.issuer.unwrap().as_bytes(),
    );*/
    let totp = Totp::new(args.issuer.unwrap());
    dbg!(&totp);
    dbg!(&totp.get());
}
