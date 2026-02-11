use ratls::{InternalTokenResolver, RaTlsCertResolver, TokenFromFile, load_root_cert_store};
use rustls::{crypto::ring::default_provider, ClientConfig};
use std::sync::Arc;

use crate::GenericResult;
use crate::token::IoctlTokenResolver;

#[derive(clap::ValueEnum, Default, Debug, Clone)]
pub enum Protocol
{
    #[default]
    NoTLS,
    TLS,
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
    default_provider()
        .install_default()
        .expect("Could not install CryptoProvider");

    let root_cert_store = load_root_cert_store(config.root_ca)?;
    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    Ok(tls_config)
}

pub(crate) fn ratls_client_config(config: Config) -> GenericResult<ClientConfig>
{
    default_provider()
        .install_default()
        .expect("Could not install CryptoProvider");

    let root_cert_store = load_root_cert_store(config.root_ca)?;
    let token_resolver: Arc<dyn InternalTokenResolver> = match config.token {
        Some(path) => Arc::new(TokenFromFile::from_path(path)?),
        None => Arc::new(IoctlTokenResolver()),
    };
    let resolver = Arc::new(RaTlsCertResolver::from_token_resolver(token_resolver)?);

    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_cert_resolver(resolver);

    Ok(tls_config)
}
