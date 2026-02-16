use ratls::{InternalTokenResolver, RaTlsCertResolver, TokenFromFile, load_root_cert_store};
use rustls::ClientConfig;
use std::sync::Arc;

use crate::{GenericResult, token, utils};

#[derive(clap::ValueEnum, Default, Debug, Clone)]
pub enum Protocol
{
    NoTLS,
    TLS,
    #[default]
    RaTLS,
}

#[derive(Debug)]
pub struct Config
{
    pub root_ca: String,
    pub tls: Protocol,
    pub token: Option<String>,
}

pub(crate) fn tls_client_config(config: Config) -> GenericResult<ClientConfig>
{
    utils::install_default_crypto_provider()?;

    let root_cert_store = load_root_cert_store(&config.root_ca)
        .map_err(|e| format!("Failed to load root-ca \"{}\": {}", config.root_ca, e))?;
    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    Ok(tls_config)
}

pub(crate) fn ratls_client_config(config: Config) -> GenericResult<ClientConfig>
{
    utils::install_default_crypto_provider()?;

    let root_cert_store = load_root_cert_store(&config.root_ca)
        .map_err(|e| format!("Failed to load root-ca \"{}\": {}", config.root_ca, e))?;
    let token_resolver: Arc<dyn InternalTokenResolver> = match config.token {
        Some(path) => Arc::new(
            TokenFromFile::from_path(&path)
                .map_err(|e| format!("Failed to load token: \"{}\": {}", path, e))?,
        ),
        None => Arc::new(token::IoctlTokenResolver()),
    };
    let resolver = Arc::new(RaTlsCertResolver::from_token_resolver(token_resolver)?);

    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_cert_resolver(resolver);

    Ok(tls_config)
}
