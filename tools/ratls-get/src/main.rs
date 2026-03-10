use std::fs::File;
use std::path::{Path, PathBuf};

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

    /// URL of the file to download, protocol can be ommited
    #[arg(short, long, default_value = "localhost:1337/example.txt")]
    url: String,

    /// Output path to save the downloaded file (can be directory or filename)
    #[clap(short, long, default_value = ".")]
    output: String,

    /// TLS variant to use
    #[arg(short, long, default_value_t, value_enum)]
    tls: TlsProtocol,

    /// Use dummy token from file (useful for testing)
    #[arg(short = 'f', long)]
    token: Option<String>,

    /// Continue getting a partially downloaded file
    #[arg(short, long = "continue")]
    cont: bool,
}

fn get_listing(client: &Client, url: &str) -> Result<(), Box<dyn std::error::Error>>
{
    info!("Getting listing: {}", url);
    let (response, content_type, content_length) = client.get(url, None)?;
    info!(
        "Received response: Content-type: \"{}\"; Content-length: {}",
        content_type, content_length
    );

    let listing = response.bytes()?;
    let listing = String::from_utf8_lossy(&listing);
    info!("{}", listing);

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    let cli = Cli::parse();
    info!("{:#?}", cli);

    if !cli.url.contains('/') {
        return Err("Address needs to contain a path, at least '/' after hostname".into());
    }

    let config = TlsConfig {
        root_ca: cli.root_ca,
        tls: cli.tls,
        token: cli.token,
    };

    let client = Client::from_config(config)?;

    // handle listing case
    if cli.url.ends_with('/') {
        return get_listing(&client, &cli.url);
    }

    let output_path = Path::new(&cli.output);
    // distinguish a case where output is either a directory or a filepath
    let savepath = if cli.output.ends_with('/') || output_path.is_dir() {
        // compose the savepath from an output directory and URL filename
        let filename = cli
            .url
            .split('/')
            .last()
            .ok_or(format!("URL doesn't contain a filename: {}", cli.url))?;
        PathBuf::from(cli.output).join(filename)
    } else {
        // it's not a directory, return verbatim
        output_path.to_path_buf()
    };

    let (mut file, length) = if cli.cont && savepath.exists() {
        info!("Continuing download as: \"{}\"", savepath.display());
        let file = File::options().write(true).append(true).open(&savepath)?;
        let length = file.metadata()?.len();
        (file, Some(length))
    } else {
        info!("Saving as: \"{}\"", savepath.display());
        (File::create(&savepath)?, None)
    };

    info!("Downloading: {}", cli.url);
    let (mut response, content_type, content_length) = client.get(&cli.url, length)?;
    info!(
        "Received response: Content-type: \"{}\"; Content-length: {}",
        content_type, content_length
    );
    std::io::copy(&mut response, &mut file)?;

    let skipped = length.unwrap_or(0);
    let bytes_saved = file.metadata()?.len() - skipped;
    drop(file); // close the file now in case we remove it below

    if bytes_saved as usize != content_length {
        std::fs::remove_file(&savepath)?;
        Err(format!(
            "Number of bytes expected ({}) doesn't match bytes saved ({})",
            content_length, bytes_saved
        )
        .into())
    } else {
        info!("Downloaded {} bytes", bytes_saved);
        Ok(())
    }
}
