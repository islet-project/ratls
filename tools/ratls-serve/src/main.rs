use clap::{Parser, ValueEnum};
use log::{debug, info};

#[derive(ValueEnum, Default, Debug, Clone)]
pub enum Protocol {
    #[default]
    NoTLS,
    TLS,
    RaTLS,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli
{
    /// runtime server root directory
    #[arg(short, long, default_value = ".")]
    root: String,

    /// path to server certificate
    #[arg(short, long, default_value = "./certs/server.crt")]
    cert: String,

    /// path to server private key
    #[arg(short, long, default_value = "./certs/server.key")]
    key: String,

    /// TLS variant to use
    #[arg(short, long, default_value_t, value_enum)]
    tls: Protocol,

    /// server port
    #[arg(short, long, default_value_t = 1337)]
    port: u16,

    /// RA-TLS: Veraison verification service host
    #[arg(short = 'u', long, default_value = "https://localhost:8080")]
    veraison_url: String,

    /// RA-TLS: Veraisons public key
    #[arg(short = 'v', long, default_value = "./ratls/pkey.jwk")]
    veraison_pubkey: String,

    /// RA-TLS: JSON containing reference values
    #[arg(short = 'j', long, default_value = "./ratls/example.json")]
    reference_json: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    let cli = Cli::parse();

    debug!("DEBUG");
    info!("{:#?}", cli);

    Ok(())
}
