use clap::Parser;

/// A simple time-based one-time password generator
#[derive(Parser)]
struct Config {
    /// The issuer of the key
    issuer: String,
}

fn main() {
    let _args = Config::parse();
}
