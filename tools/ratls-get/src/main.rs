use clap::{Parser, ValueEnum};
use log::{debug, info};

#[derive(ValueEnum, Default, Debug, Clone)]
pub enum Protocol {
    #[default]
    NoTLS,
    TLS,
    RaTLS,
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli
{
    /// Root certificate file in PEM format (used with tls and ra-tls)
    #[arg(short, long, default_value = "./certs/root-ca.crt")]
    root_ca: String,

    /// URL of the file to download, omit the protocol
    #[arg(short, long, default_value = "localhost:1337/example.txt")]
    url: String,

    /// Directory to save the downloaded file
    #[clap(short, long, default_value = ".")]
    dir: String,

    /// TLS variant to use
    #[arg(short, long, default_value_t, value_enum)]
    tls: Protocol,
}

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    let cli = Cli::parse();

    debug!("DEBUG");
    info!("{:#?}", cli);

    Ok(())
}
