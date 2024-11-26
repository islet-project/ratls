mod resolver;

use std::io::Write;
use std::sync::Arc;

use clap::Parser;
use log::info;
use ratls::{InternalTokenResolver, RaTlsClient, TokenFromFile};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to root CA cert
    #[arg(short, long)]
    root_ca: String,

    /// URL to ratls server
    #[arg(short = 'u', long, default_value = "localhost:1337")]
    server_url: String,

    /// Server name, overridden if server is attested
    #[clap(short = 'n', long, default_value = "localhost")]
    server_name: String,

    /// Use dummy token from file (useful for testing)
    #[arg(short, long)]
    token: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ratls::init_logger();

    let args = Args::parse();

    let resolver: Arc<dyn InternalTokenResolver> = if let Some(token) = args.token {
        Arc::new(TokenFromFile::from_path(token)?)
    } else {
        Arc::new(resolver::IoctlTokenResolver())
    };

    let client = RaTlsClient::new(ratls::ClientMode::AttestedClient {
        client_token_resolver: resolver,
        root_ca_path: args.root_ca,
    })?;

    let mut connection = client.connect(args.server_url, args.server_name)?;
    info!("Connection established");
    write!(connection.stream(), "GIT")?;
    info!("Work finished, exiting");

    Ok(())
}
