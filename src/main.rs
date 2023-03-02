use clap::Parser;

/// A simple time-based one-time password generator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// The issuer of the key
    issuer: Option<String>,
}

fn main() {
    let args = Config::parse();
    dbg!(args);
}
