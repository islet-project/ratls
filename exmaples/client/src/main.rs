use std::{sync::Arc};
use std::io::Write;

use clap::Parser;
use log::info;
use ratls::{RaTlsClient, TokenFromFile};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to root CA cert
    #[arg(short, long)]
    root_ca: String,

    /// Url to ratls server
    #[arg(short = 'u', long, default_value = "localhost:1337")]
    server_url: String,

    /// Server name, overriden if server is attested
    #[clap(short = 'n', long, default_value = "localhost")]
    server_name: String,

    /// Use dummy token from file (usefull for testing)
    #[arg(short, long)]
    token: Option<String>
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ratls::init_logger();

    let args = Args::parse();

    let client = RaTlsClient::new(ratls::ClientMode::AttestedClient {
        client_token_resolver: Arc::new(TokenFromFile::from_path(args.token.expect("In demo mode token needs to be provided from file"))?),
        root_ca_path: args.root_ca
    })?;

    let mut connection = client.connect(args.server_url, args.server_name)?;
    info!("Connection established");
    write!(connection.stream(), "GIT")?;
    info!("Work finished, exiting");

    Ok(())
}
