use std::{net::TcpListener, sync::Arc};
use rustls::{ServerConfig, ServerConnection};
use crate::{cert_resolver::RaTlsCertResolver, cert_verifier::RaTlsCertVeryfier, error::RaTlsError, tools::{self, load_certificates_from_pem, load_private_key_from_file}};
use crate::connection::RaTlsConnection;
use crate::token_resolver::InternalTokenResolver;
use crate::token_verifier::InternalTokenVerifier;
use std::io::{Read, Write};

pub enum ServerMode {
    AttestedClient {
        client_token_verifier: Arc<dyn InternalTokenVerifier>,
        server_certificate_path: String,
        server_privatekey_path: String,
    },
    AttestedServer {
        server_token_resolver: Arc<dyn InternalTokenResolver>
    },
    MutualAttestation {
        client_token_verifier: Arc<dyn InternalTokenVerifier>,
        server_token_resolver: Arc<dyn InternalTokenResolver>
    }
}

pub struct RaTlsConnectionsIterator {
    config: Arc<ServerConfig>,
    listener: TcpListener
}

impl RaTlsConnectionsIterator {
    pub fn new(config: Arc<ServerConfig>, listener: TcpListener) -> Self {
        Self { config, listener }
    }

    fn accept_connection(&self) -> Result<RaTlsConnection<ServerConnection>, RaTlsError> {
        let conn = ServerConnection::new(self.config.clone())?;
        let sock = self.listener.accept()?.0;

        let mut tlsconn = RaTlsConnection::new(sock, conn);
        self.handshake(&mut tlsconn)?;
        Ok(tlsconn)
    }

    fn handshake(&self, conn: &mut RaTlsConnection<ServerConnection>) -> Result<(), RaTlsError> {
        let mut stream = conn.stream();
        let msg = "HELO";

        stream.write_all(msg.as_bytes())?;
        stream.flush()?;

        let mut resp = vec![0; msg.len()];
        stream.read_exact(&mut resp)?;

        if resp.as_slice() == msg.as_bytes() {
            Ok(())
        } else {
            Err(RaTlsError::HandshakeError)
        }
    }
}

impl Iterator for RaTlsConnectionsIterator {
    type Item = Result<RaTlsConnection<ServerConnection>, RaTlsError>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.accept_connection())
    }
}

pub struct RaTlsServer {
    mode: ServerMode
}

impl RaTlsServer {
    pub fn new(mode: ServerMode) -> Result<Self, RaTlsError> {
        Ok(Self { mode })
    }

    fn make_server_config(&self) -> Result<ServerConfig, RaTlsError> {
        tools::install_default_crypto_provider();
        match &self.mode {
            ServerMode::AttestedClient { client_token_verifier, server_certificate_path, server_privatekey_path } => {
                Ok(ServerConfig::builder()
                    .with_client_cert_verifier(Arc::new(RaTlsCertVeryfier::from_token_verifier(client_token_verifier.clone())))
                    .with_single_cert(
                        load_certificates_from_pem(server_certificate_path)?,
                        load_private_key_from_file(server_privatekey_path)?
                    )?
                )
            },
            ServerMode::AttestedServer { server_token_resolver } => {
                Ok(ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(RaTlsCertResolver::from_token_resolver(server_token_resolver.clone())?))
                )
            },
            ServerMode::MutualAttestation { client_token_verifier, server_token_resolver } => {
                Ok(ServerConfig::builder()
                    .with_client_cert_verifier(Arc::new(RaTlsCertVeryfier::from_token_verifier(client_token_verifier.clone())))
                    .with_cert_resolver(Arc::new(RaTlsCertResolver::from_token_resolver(server_token_resolver.clone())?))
                )
            }
        }
    }

    pub fn connections(&self, bind_address: impl AsRef<str>) -> Result<RaTlsConnectionsIterator, RaTlsError> {
        Ok(RaTlsConnectionsIterator::new(
            Arc::new(self.make_server_config()?),
            TcpListener::bind(bind_address.as_ref())?
        ))
    }
}
