use std::path::{Path, PathBuf};
use std::{fs, io};

use clap::Parser;
use log::{error, info};

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

    /// Number of retries in case of a timeout
    #[arg(short = 'n', long, default_value = "3")]
    retry: u16,
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
    append: bool,
) -> Result<(fs::File, Option<u64>), Box<dyn std::error::Error>>
{
    if append && save_path.exists() {
        info!("Continuing download as: \"{}\"", save_path.display());
        let file = fs::File::options().append(true).open(&save_path)?;
        let length = file.metadata()?.len();
        Ok((file, Some(length)))
    } else {
        info!("Saving as: \"{}\"", save_path.display());
        Ok((fs::File::create(save_path)?, None))
    }
}

/// Check the error and all possible inner errors for timeout.
///
/// The most often case is a custom io_err (returned from io::copy) that embeds
/// reqwest_err that embeds hyper_err that is a timeout (but it's not the only
/// possibility), hence such a deep check is actually required.
fn err_is_timeout(err: &(dyn std::error::Error + 'static)) -> bool
{
    // first check the error itself before we go deeper
    let mut source = Some(err);

    while let Some(err) = source {
        if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
            // this function checks all inner reqwest/hyper/io errors
            if reqwest_err.is_timeout() {
                return true;
            }
        }
        if let Some(io_err) = err.downcast_ref::<io::Error>() {
            if io_err.kind() == io::ErrorKind::TimedOut {
                return true;
            }
        }
        source = err.source();
    }

    false
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
        info!("Getting listing: {}", cli.url);
        let listing = client.list_dir(&cli.url)?;
        info!("{}", serde_json::to_string_pretty(&listing)?);
        return Ok(());
    }

    // values to be used in a loop below
    let save_path = get_save_path(&cli.output, &cli.url)?;
    let mut append = cli.cont;
    let mut tries_left = cli.retry;

    let (content_length, bytes_saved) = loop {
        let (mut file, length) = open_file(&save_path, append)?;
        info!("Downloading: {}; Skipping: {:?}", cli.url, length);
        let content_length = match client.download_file(&cli.url, &mut file, length) {
            Ok(content_len) => content_len,
            Err(e) => {
                if tries_left > 0 && err_is_timeout(e.as_ref()) {
                    info!("Download timed out, {} tries left...", tries_left);
                    append = true;
                    tries_left = tries_left - 1;
                    continue;
                } else {
                    error!("Failed to download: {:#?}", e);
                    Err(e)?
                }
            }
        };

        let skipped = length.unwrap_or(0);
        let bytes_saved = file.metadata()?.len() - skipped;

        break (content_length, bytes_saved);
    };

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
