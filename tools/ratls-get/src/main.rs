use std::io;
use std::path::{Path, PathBuf};
use tokio::fs;

use clap::Parser;
use log::{error, info};

use ratls_get::{Client, GenericResult, TlsConfig, TlsProtocol};

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

    /// The Context ID for vsock connection
    #[arg(short = 'i', long)]
    vsock_cid: Option<u32>,

    /// The port for vsock connection
    #[arg(short = 'p', long)]
    vsock_port: Option<u32>,

    /// Timeout in seconds for HTTP requests (default: 60)
    #[arg(long, default_value = "60")]
    timeout_secs: u64,
}

/// Figure out a final path to the file to save including its filename
fn get_save_path(output: &str, url: &str) -> GenericResult<PathBuf>
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
async fn open_file(save_path: &Path, append: bool) -> GenericResult<(fs::File, Option<u64>)>
{
    if append && save_path.exists() {
        info!("Continuing download as: \"{}\"", save_path.display());
        let file = fs::OpenOptions::new().append(true).open(&save_path).await?;
        let length = file.metadata().await?.len();
        Ok((file, Some(length)))
    } else {
        info!("Saving as: \"{}\"", save_path.display());
        Ok((fs::File::create(save_path).await?, None))
    }
}

/// Check the error for timeout.
///
/// Checks if the error or any of its sources is an IO timeout error.
fn err_is_timeout(err: &(dyn std::error::Error + 'static)) -> bool
{
    let mut source = Some(err);

    while let Some(err) = source {
        if let Some(io_err) = err.downcast_ref::<io::Error>() {
            if io_err.kind() == io::ErrorKind::TimedOut {
                return true;
            }
        }
        source = err.source();
    }

    false
}

#[tokio::main]
async fn main() -> GenericResult<()>
{
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    let cli = Cli::parse();
    info!("{:#?}", cli);

    if !cli.url.contains('/') {
        return Err("Address needs to contain a path, at least '/' after hostname".into());
    }

    let tls_config = TlsConfig {
        root_ca: cli.root_ca,
        tls: cli.tls,
        token: cli.token,
    };

    let client = Client::new(tls_config, cli.vsock_cid, cli.vsock_port, cli.timeout_secs).await?;

    // handle listing case
    if cli.url.ends_with('/') {
        info!("Getting listing: {}", cli.url);
        let listing = client.list_dir(&cli.url).await?;
        info!("{}", serde_json::to_string_pretty(&listing)?);
        return Ok(());
    }

    // values to be used in a loop below
    let save_path = get_save_path(&cli.output, &cli.url)?;
    let mut append = cli.cont;
    let mut tries_left = cli.retry;

    let (content_length, bytes_saved) = loop {
        let (mut file, length) = open_file(&save_path, append).await?;
        info!("Downloading: {}; Skipping: {:?}", cli.url, length);
        let content_length = match client.download_file(&cli.url, &mut file, length).await {
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
        let bytes_saved = file.metadata().await?.len() - skipped;

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
