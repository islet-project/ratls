use std::path::PathBuf;

use clap::Parser;
use log::info;

use ratls_get::{Client, TlsConfig, TlsProtocol};

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
    tls: TlsProtocol,

    /// Use dummy token from file (useful for testing)
    #[arg(short = 'f', long)]
    token: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    let cli = Cli::parse();

    info!("{:#?}", cli);

    let config = TlsConfig {
        root_ca: cli.root_ca,
        tls: cli.tls,
        token: cli.token,
    };

    let client = Client::from_config(config)?;

    let filename = cli
        .url
        .split('/')
        .last()
        .ok_or(format!("URL doesn't contain a filename: {}", cli.url))?;
    let savepath = PathBuf::from(cli.dir).join(filename);

    info!("Downloading: {}", cli.url);
    let mut response = client.get_file(&cli.url)?;
    let mut file = std::fs::File::create(&savepath)?;
    std::io::copy(&mut response, &mut file)?;

    let bytes_saved = file.metadata()?.len();
    info!(
        "Downloaded {} bytes, saved as: \"{}\"",
        bytes_saved,
        savepath.display()
    );

    Ok(())
}
