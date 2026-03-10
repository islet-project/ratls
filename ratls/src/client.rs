use std::{net::TcpStream, sync::Arc};
use rustls::{pki_types::{DnsName, ServerName}, ClientConfig, ClientConnection};
use crate::{cert_resolver::RaTlsCertResolver, cert_verifier::RaTlsCertVeryfier,
    error::RaTlsError, tools::{self, load_certificates_from_pem, load_private_key_from_file, load_root_cert_store}};
use crate::connection::RaTlsConnection;
use crate::token_resolver::InternalTokenResolver;
use crate::token_verifier::InternalTokenVerifier;
use std::io::{Read, Write};

pub enum ClientMode {
    AttestedClient {
        client_token_resolver: Arc<dyn InternalTokenResolver>,
        root_ca_path: String
    },
    AttestedServer {
        client_certificate_path: String,
        client_privatekey_path: String,
        server_token_verifier: Arc<dyn InternalTokenVerifier>
    },
    MutualAttestation {
        client_token_resolver: Arc<dyn InternalTokenResolver>,
        server_token_verifier: Arc<dyn InternalTokenVerifier>
    }
}

pub struct RaTlsClient {
    mode: ClientMode
}

impl RaTlsClient {
    pub fn new(mode: ClientMode) -> Result<Self, RaTlsError> {
        Ok(Self { mode })
    }

    fn make_client_config(&self) -> Result<(ClientConfig, Option<String>), RaTlsError> {
        tools::install_default_crypto_provider();
        match &self.mode {
            ClientMode::AttestedClient { client_token_resolver, root_ca_path } => {
                Ok((ClientConfig::builder()
                        .with_root_certificates(load_root_cert_store(root_ca_path)?)
                        .with_client_cert_resolver(Arc::new(RaTlsCertResolver::from_token_resolver(client_token_resolver.clone())?)),
                    None
                ))
            },
            ClientMode::AttestedServer { client_certificate_path, client_privatekey_path, server_token_verifier } => {
                let verifier = RaTlsCertVeryfier::from_token_verifier(server_token_verifier.clone());
                let chall = verifier.b64_challenge();
                Ok((ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_client_auth_cert(
                        load_certificates_from_pem(client_certificate_path)?,
                        load_private_key_from_file(client_privatekey_path)?
                    )?,
                    Some(chall)
                ))
            },
            ClientMode::MutualAttestation { client_token_resolver, server_token_verifier } => {
                let verifier = RaTlsCertVeryfier::from_token_verifier(server_token_verifier.clone());
                let chall = verifier.b64_challenge();
                Ok((ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_client_cert_resolver(Arc::new(RaTlsCertResolver::from_token_resolver(client_token_resolver.clone())?)),
                    Some(chall)
                ))
            }
        }
    }

    pub fn connect(&self, server_url: String, server_name: String) -> Result<RaTlsConnection<ClientConnection>, RaTlsError> {
        let sock = TcpStream::connect(server_url)?;
        let (config, challenge) = self.make_client_config()?;
        let conn = ClientConnection::new(
            Arc::new(config),
            ServerName::DnsName(DnsName::try_from(challenge.unwrap_or(server_name))?)
        )?;

        let mut tlsconn = RaTlsConnection::new(sock, conn);
        self.handshake(&mut tlsconn)?;
        Ok(tlsconn)
    }

    fn handshake(&self, conn: &mut RaTlsConnection<ClientConnection>) -> Result<(), RaTlsError> {
        let mut stream = conn.stream();
        let msg = "HELO";

        let mut resp = vec![0; msg.len()];
        stream.read_exact(&mut resp)?;

        stream.write_all(msg.as_bytes())?;
        stream.flush()?;

        if resp.as_slice() == msg.as_bytes() {
            Ok(())
        } else {
            Err(RaTlsError::HandshakeError)
        }
    }
}
