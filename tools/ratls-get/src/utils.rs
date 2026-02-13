use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap};
use rustls::crypto::ring::default_provider;

use crate::GenericResult;

pub(crate) fn install_default_crypto_provider() -> GenericResult<()>
{
    default_provider()
        .install_default()
        .map_err(|e| format!("Could not install default crypto provider: {:?}", e))?;

    Ok(())
}

pub(crate) fn content_type(headers: &HeaderMap) -> Option<String>
{
    headers
        .get(CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok().map(|ct| ct.to_string()))
}

pub(crate) fn content_length(headers: &HeaderMap) -> Option<usize>
{
    headers
        .get(CONTENT_LENGTH)
        .and_then(|cl| cl.to_str().ok().map(|cl| cl.parse().ok()))?
}
