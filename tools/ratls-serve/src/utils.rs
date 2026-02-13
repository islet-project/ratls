use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::GenericResult;

pub(crate) fn load_certificates_from_pem<'a, T: AsRef<Path>>(
    path: T,
) -> std::io::Result<Vec<CertificateDer<'a>>>
{
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect()
}

pub(crate) fn load_private_key_from_file<'a, T>(path: T) -> GenericResult<PrivateKeyDer<'a>>
where
    T: AsRef<Path> + std::fmt::Display,
{
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);
    let mut keys =
        rustls_pemfile::pkcs8_private_keys(&mut reader).collect::<Result<Vec<_>, _>>()?;
    match keys.len() {
        0 => Err(format!("No PKCS8-encoded private key found in {path}").into()),
        1 => Ok(PrivateKeyDer::Pkcs8(keys.remove(0))),
        _ => Err(format!("More than one PKCS8-encoded private key found in {path}").into()),
    }
}

pub(crate) fn install_default_crypto_provider() -> GenericResult<()>
{
    default_provider()
        .install_default()
        .map_err(|e| format!("Could not install default crypto provider: {:?}", e))?;

    Ok(())
}
