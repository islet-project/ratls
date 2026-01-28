use log::{debug, info, error};
use rcgen::{CertificateParams, KeyPair, CustomExtension, date_time_ymd, DistinguishedName};
use rsa::RsaPrivateKey;
use rustls::{client::ResolvesClientCert,
             server::ResolvesServerCert,
             sign::CertifiedKey,
             crypto::ring::sign::any_supported_type,
             pki_types::PrivateKeyDer,
};
use std::sync::Arc;
use rand::rngs::OsRng;
use pkcs8::{EncodePrivateKey, EncodePublicKey};
use crate::{error::RaTlsError, tools::hash_realm_challenge, config::CCA_TOKEN_X509_EXT};
use crate::token_resolver::InternalTokenResolver;
use base64::{Engine, engine::general_purpose::STANDARD as b64};

#[derive(Debug)]
pub struct RaTlsCertResolver {
    token_resolver: Arc<dyn InternalTokenResolver>,
    private_key: RsaPrivateKey
}

impl RaTlsCertResolver {
    pub fn from_token_resolver(token_resolver: Arc<dyn InternalTokenResolver>) -> Result<Self, RaTlsError> {
        let key_size = 2048;

        info!("Generating RSA {}bit key.", key_size);
        let private_key = RsaPrivateKey::new(&mut OsRng, key_size)?;
        info!("Finished generating RSA key.");

        Ok(Self {
            token_resolver,
            private_key
        })
    }

    fn create_cert(&self, challenge: String) -> Result<Arc<CertifiedKey>, RaTlsError> {
        debug!("Received challenge {}", challenge);
        let realm_challenge = hash_realm_challenge(
            b64.decode(challenge)?.as_slice(),
            self.private_key
                .to_public_key()
                .to_public_key_der()?
                .as_bytes()
        );

        let token = match self.token_resolver.resolve(&realm_challenge) {
            Err(e) => {
                error!("Failed to acquire token from the token_resolver: {}", e);
                return Err(e);
            },
            Ok(token) => token,
        };
        let pkcs8_privkey = self.private_key.to_pkcs8_der()?;
        // We are decoding DER created by RustCrypto,
        // this has no right to fail.
        let privkey = PrivateKeyDer::try_from(pkcs8_privkey.as_bytes()).unwrap();
        let mut params = CertificateParams::default();
        let key_pair = KeyPair::try_from(pkcs8_privkey.as_bytes())?;

        params.not_before = date_time_ymd(2021, 05, 19);
        params.not_after = date_time_ymd(4096, 01, 01);
        params.distinguished_name = DistinguishedName::new();

        params.custom_extensions.push(CustomExtension::from_oid_content(
            CCA_TOKEN_X509_EXT.as_vec::<u64>()?.as_slice(),
            token
        ));

        let cert = params.self_signed(&key_pair)?.der().to_owned();
        let key = any_supported_type(&privkey)?;

        Ok(Arc::new(CertifiedKey::new(vec![cert], key)))
    }
}

impl ResolvesClientCert for RaTlsCertResolver {
    fn has_certs(&self) -> bool {
        true
    }

    fn resolve(
            &self,
            acceptable_issuers: &[&[u8]],
            _sigschemes: &[rustls::SignatureScheme],
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {

        if acceptable_issuers.len() != 1 {
            return None;
        }

        if let Ok(challenge) = String::from_utf8(acceptable_issuers[0].to_owned()) {
            self.create_cert(challenge).ok()
        } else {
            None
        }
    }
}

impl ResolvesServerCert for RaTlsCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(challenge) = client_hello.server_name() {
            self.create_cert(challenge.to_owned()).ok()
        } else {
            None
        }
    }
}
