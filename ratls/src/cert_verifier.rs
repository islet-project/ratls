use std::sync::Arc;
use log::{error, info};
use pkcs8::EncodePublicKey;
use rand::RngCore;
use base64::{Engine, engine::general_purpose::STANDARD as b64};
use rust_rsi::{verify_token, print_token, RealmClaims};
use rustls::pki_types::{ServerName, UnixTime};
use x509_certificate::X509Certificate;
use crate::{token_verifier::InternalTokenVerifier, config::CCA_TOKEN_X509_EXT, tools::hash_realm_challenge};
use rustls::{client::danger::{ServerCertVerified, ServerCertVerifier}, crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms}, pki_types::CertificateDer, server::danger::{ClientCertVerified, ClientCertVerifier}, DistinguishedName, Error, SignatureScheme};
use webpki::ring as webpki_algs;
use crate::error::RaTlsError;

// Copied from rustls v0.21 implementation of WebPkiVerifier
static SUPPORTED_SIG_SCHEMES: [SignatureScheme; 9] = [
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

// Copied from rustls v0.23 implementation of crypto::ring
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ED25519,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

#[derive(Debug)]
pub struct RaTlsCertVeryfier {
    token_verifier: Arc<dyn InternalTokenVerifier>,
    challenge: [u8; 64],
    root_subjects: Vec<DistinguishedName>
}

impl RaTlsCertVeryfier {
    pub fn from_token_verifier(token_verifier: Arc<dyn InternalTokenVerifier>) -> Self {
        let mut challenge = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut challenge);
        let root_subjects = vec![
            DistinguishedName::from(b64.encode(challenge).as_bytes().to_owned())
        ];

        Self { token_verifier, challenge, root_subjects}
    }

    pub fn b64_challenge(&self) -> String {
        b64.encode(self.challenge)
    }

    fn fetch_token<'a>(&self, cert: &'a X509Certificate) -> Result<&'a [u8], RaTlsError> {
        for ext in cert.iter_extensions() {
            if ext.id.0.as_ref() == CCA_TOKEN_X509_EXT.as_raw()?.as_slice() {
                return Ok(ext.value.as_slice().ok_or(RaTlsError::CannotExtractTokenFromExtension)?);
            }
        }
        error!("Token is missing in certificate");
        Err(RaTlsError::MissingTokenInCertificate)
    }

    fn verify_cert(&self, cert_der: &CertificateDer) -> Result<(), RaTlsError> {
        let cert = X509Certificate::from_der(cert_der.to_vec())?;
        let pubkey = cert.to_public_key_der()?;
        let raw_token = self.fetch_token(&cert)?;
        let token = verify_token(raw_token, None).map_err(|e| {error!("Token verification failed"); e})?;
        let realm_claims = RealmClaims::from_raw_claims(&token.realm_claims.token_claims, &token.realm_claims.measurement_claims)?;
        let hash = hash_realm_challenge(
            self.challenge.as_slice(),
            pubkey.as_bytes()
        );

        if hash != realm_claims.challenge {
            error!("Challenge mismatch, expected: {:?} and got {:?}", self.challenge, realm_claims.challenge);
            #[cfg(not(feature = "disable_challenge"))]
            return Err(RaTlsError::InvalidChallenge);
        }

        info!("Received client CCA token:");
        print_token(&token);

        self.token_verifier.verify(raw_token).map_err(|e|{error!("Token verification failed"); e})
    }
}

impl ClientCertVerifier for RaTlsCertVeryfier {
    fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
        match self.verify_cert(end_entity) {
            Ok(()) => Ok(ClientCertVerified::assertion()),
            Err(err) => Err(Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(err)))))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message, cert, dss,
            &SUPPORTED_SIG_ALGS
        )
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_subjects
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        SUPPORTED_SIG_SCHEMES.to_vec()
    }
}

impl ServerCertVerifier for RaTlsCertVeryfier {
    fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
        match self.verify_cert(end_entity) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(err) => Err(Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(err)))))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SIG_SCHEMES.to_vec()
    }
}
