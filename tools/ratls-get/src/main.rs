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

/// Handle simplified listing request case that doesn't save any file
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

/// Figure out a final path to the file to save including its filename
fn get_save_path(output: &str, url: &str) -> Result<PathBuf, Box<dyn std::error::Error>>
{
    let output_path = Path::new(&output);

    // distinguish a case where output is either a directory or a filepath
    if output.ends_with('/') || output_path.is_dir() {
        // compose the savepath from an output directory and URL filename
        let filename = url
            .split('/')
            .next_back()
            .ok_or(format!("URL doesn't contain a filename: {}", url))?;
        Ok(output_path.join(filename))
    } else {
        // it's not a directory, return verbatim
        Ok(output_path.to_path_buf())
    }
}

/// Create new file or append to an existing one returning its length
fn open_file(
    save_path: &Path,
    cont: bool,
) -> Result<(File, Option<u64>), Box<dyn std::error::Error>>
{
    if cont && save_path.exists() {
        info!("Continuing download as: \"{}\"", save_path.display());
        let file = File::options().append(true).open(&save_path)?;
        let length = file.metadata()?.len();
        Ok((file, Some(length)))
    } else {
        info!("Saving as: \"{}\"", save_path.display());
        Ok((File::create(save_path)?, None))
    }
}

/// Actually perform the HTTP request and download the file
fn download_file(
    client: &Client,
    url: &str,
    file: &mut File,
    skip: Option<u64>,
) -> Result<u64, Box<dyn std::error::Error>>
{
    info!("Downloading: {}; Skipping: {:?}", url, skip);
    let (mut response, content_type, content_length) = client.get(url, skip)?;
    info!(
        "Received response: Content-type: \"{}\"; Content-length: {}",
        content_type, content_length
    );
    std::io::copy(&mut response, file)?;

    Ok(content_length as u64)
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

    let save_path = get_save_path(&cli.output, &cli.url)?;
    let (mut file, length) = open_file(&save_path, cli.cont)?;
    let content_length = download_file(&client, &cli.url, &mut file, length)?;

    let skipped = length.unwrap_or(0);
    let bytes_saved = file.metadata()?.len() - skipped;
    drop(file); // close the file now in case we remove it below

    if bytes_saved != content_length {
        std::fs::remove_file(&save_path)?;
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
