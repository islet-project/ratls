use rustls::crypto::ring::default_provider;

use crate::GenericResult;

pub(crate) fn install_default_crypto_provider() -> GenericResult<()>
{
    default_provider()
        .install_default()
        .map_err(|e| format!("Could not install default crypto provider: {:?}", e))?;

    Ok(())
}
