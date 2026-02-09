use clap::Parser;
use log::{error, info};

use ratls_serve::SimpleFiles;
use ratls_serve::httpd_run;
use ratls_serve::{TlsConfig, TlsProtocol};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli
{
    /// runtime server root directory
    #[arg(short, long, default_value = "./root")]
    root: String,

    /// path to server certificate
    #[arg(short, long, default_value = "./certs/server.crt")]
    cert: String,

    /// path to server private key
    #[arg(short, long, default_value = "./certs/server.key")]
    key: String,

    /// TLS variant to use
    #[arg(short, long, default_value_t, value_enum)]
    tls: TlsProtocol,

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>
{
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    let cli = Cli::parse();

    info!("{:#?}", cli);

    let config = TlsConfig {
        cert: cli.cert,
        key: cli.key,
        tls: cli.tls,
        port: cli.port,
        veraison_url: cli.veraison_url,
        veraison_pubkey: cli.veraison_pubkey,
        reference_json: cli.reference_json,
    };

    let files = SimpleFiles::new(&cli.root);
    info!("Launching the HTTP(S) server");
    if let Result::Err(e) = httpd_run(files, config).await {
        error!("{}", e);
    }

    Ok(())
}
