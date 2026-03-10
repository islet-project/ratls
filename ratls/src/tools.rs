use std::{fs::File, io::Read};
use std::io::BufReader;
use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use rustls::{pki_types::{CertificateDer, PrivateKeyDer}, RootCertStore};
use sha2::{Digest, Sha512};

use crate::error::RaTlsError;

pub(crate) fn load_certificates_from_pem(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader).collect()
}

pub(crate) fn load_private_key_from_file(path: &str) -> Result<PrivateKeyDer<'static>, RaTlsError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let private_key = rustls_pemfile::private_key(&mut reader)?;
    match private_key {
        None => Err(RaTlsError::PrivateKeyParsingError(format!("No PKCS8-encoded private key found in {path}"))),
        Some(key) => Ok(key),
    }
}

pub fn load_root_cert_store(path: impl AsRef<str>) -> Result<RootCertStore, RaTlsError> {
    let der_certs = load_certificates_from_pem(path.as_ref())?;
    let mut root_store = RootCertStore::empty();

    // NOTE: this probably should be interpreted
    let _ = root_store.add_parsable_certificates(der_certs);

    Ok(root_store)
}

pub(crate) fn hash_realm_challenge(challenge: &[u8], der_public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(challenge);
    hasher.update(der_public_key);
    hasher.finalize()[..].to_vec()
}

pub(crate) fn read_file(path: impl AsRef<str>) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path.as_ref())?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

pub fn init_logger() {
    env_logger::init();
}

pub fn install_default_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        default_provider().install_default().expect("Failed to install CryptoProvider");
    }
}
