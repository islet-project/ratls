use axum::{Router, extract::Request};
use futures_util::pin_mut;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::debug;
use ratls::{ChainVerifier, InternalTokenVerifier, RaTlsCertVeryfier};
use realm_verifier::{RealmVerifier, parser_json::parse_value};
use std::{fs::File, io::BufReader, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tower_service::Service;
#[cfg(not(feature = "disable-challenge-veraison"))]
use veraison_verifier::VeraisonTokenVerifer;

use crate::{GenericResult, utils};

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
    pub cert: String,
    pub key: String,
    pub tls: Protocol,
    pub port: u16,
    pub veraison_url: String,
    pub veraison_pubkey: String,
    pub reference_json: String,
}

enum TLSConfig<'a>
{
    Tls(Arc<ServerConfig>),
    RaTls(RaTLS<'a>),
}

struct RaTLS<'a>
{
    pub certs: Vec<CertificateDer<'a>>,
    pub priv_key: PrivateKeyDer<'a>,
    pub client_token_verifier: Arc<dyn InternalTokenVerifier>,
}

impl TLSConfig<'static>
{
    pub fn get_rustls_config(&self) -> GenericResult<Arc<ServerConfig>>
    {
        match self {
            Self::Tls(config) => Ok(config.clone()),
            Self::RaTls(ra_tls) => {
                let rustls_config = ServerConfig::builder()
                    .with_client_cert_verifier(Arc::new(RaTlsCertVeryfier::from_token_verifier(
                        ra_tls.client_token_verifier.clone(),
                    )))
                    .with_single_cert(ra_tls.certs.clone(), ra_tls.priv_key.clone_key())?;
                Ok(Arc::new(rustls_config))
            }
        }
    }
}

fn tls_server_config(config: Config) -> GenericResult<TLSConfig<'static>>
{
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            utils::load_certificates_from_pem(&config.cert)?,
            utils::load_private_key_from_file(&config.key)?,
        )?;

    Ok(TLSConfig::Tls(Arc::new(server_config)))
}

fn ratls_server_config(config: Config) -> GenericResult<TLSConfig<'static>>
{
    let json_reader = BufReader::new(File::open(&config.reference_json)?);
    let mut reference_json: serde_json::Value = serde_json::from_reader(json_reader)?;
    let reference_measurements = parse_value(reference_json["realm"]["reference-values"].take())?;

    let client_token_verifier = Arc::new(ChainVerifier::new(vec![
        #[cfg(not(feature = "disable-challenge-veraison"))]
        Arc::new(VeraisonTokenVerifer::new(
            &config.veraison_url,
            std::fs::read_to_string(&config.veraison_pubkey)?,
            None,
        )?),
        Arc::new(RealmVerifier::init(reference_measurements.clone())),
    ]));
    let certs = utils::load_certificates_from_pem(&config.cert)?;
    let priv_key = utils::load_private_key_from_file(&config.key)?;

    Ok(TLSConfig::RaTls(RaTLS {
        client_token_verifier,
        certs,
        priv_key,
    }))
}

pub async fn serve_tls(listener: TcpListener, app: Router, config: Config) -> GenericResult<()>
{
    debug!("Initializing TLS");

    default_provider()
        .install_default()
        .expect("Could not install CryptoProvider");

    let tls_config = tls_server_config(config)?;
    serve_internal(listener, app, tls_config).await
}

pub async fn serve_ratls(listener: TcpListener, app: Router, config: Config) -> GenericResult<()>
{
    debug!("Initializing RA-TLS");

    default_provider()
        .install_default()
        .expect("Could not install CryptoProvider");

    let tls_config = ratls_server_config(config)?;
    serve_internal(listener, app, tls_config).await
}

// For details on the code see here:
// https://github.com/tokio-rs/axum/blob/main/examples/low-level-rustls/src/main.rs
async fn serve_internal(
    listener: TcpListener,
    app: Router,
    tls_config: TLSConfig<'static>,
) -> GenericResult<()>
{
    pin_mut!(listener);

    loop {
        let tower_service = app.clone();

        let (cnx, addr) = listener.accept().await?;
        let tls_acceptor = TlsAcceptor::from(tls_config.get_rustls_config()?);

        tokio::spawn(async move {
            let Ok(stream) = tls_acceptor.accept(cnx).await else {
                log::error!("error during tls handshake connection from {}", addr);
                return;
            };

            let stream = TokioIo::new(stream);

            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                tower_service.clone().call(request)
            });

            let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(stream, hyper_service)
                .await;

            if let Err(err) = ret {
                log::warn!("error serving connection from {}: {}", addr, err);
            }
        });
    }
}
