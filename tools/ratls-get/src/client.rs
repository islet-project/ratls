use reqwest::blocking::Client as ReqwestClient;

use crate::GenericResult;
use crate::tls::{Config, Protocol, ratls_client_config, tls_client_config};

pub struct Client
{
    reqwest: ReqwestClient,
    protocol: &'static str,
}

impl Client
{
    pub fn from_config(config: Config) -> GenericResult<Self>
    {
        let protocol = match config.tls {
            Protocol::NoTLS => "http://",
            Protocol::TLS | Protocol::RaTLS => "https://",
        };

        let reqwest = match config.tls {
            Protocol::NoTLS => ReqwestClient::new(),
            Protocol::TLS => ReqwestClient::builder()
                .use_preconfigured_tls(tls_client_config(config)?)
                .build()?,
            Protocol::RaTLS => ReqwestClient::builder()
                .use_preconfigured_tls(ratls_client_config(config)?)
                .build()?,
        };

        Ok(Self { reqwest, protocol })
    }

    pub fn get_file(&self, address: &str) -> GenericResult<reqwest::blocking::Response>
    {
        let url = format!("{}{}", self.protocol, address);
        let response = self.reqwest.get(&url).send()?;
        Ok(response)
    }
}
