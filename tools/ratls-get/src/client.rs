use reqwest::blocking::{Client as ReqwestClient, Response};

use crate::tls::{Config, Protocol, ratls_client_config, tls_client_config};
use crate::{GenericResult, utils};

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

    // the response needs to contain length and type, it's an error if it doesn't
    pub fn get_file(&self, address: &str) -> GenericResult<(Response, String, usize)>
    {
        let url = format!("{}{}", self.protocol, address);

        match self.reqwest.get(&url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    let headers = response.headers();
                    let content_type = match utils::content_type(headers) {
                        Some(ct) => ct,
                        None => return Err("Response doesn't contain Content-type".into()),
                    };
                    let content_length = match utils::content_length(headers) {
                        Some(cl) => cl,
                        None => {
                            return Err("Response doesn't contain Content-length".into());
                        }
                    };
                    Ok((response, content_type, content_length))
                } else {
                    return Err(
                        format!("Response not successful: {}", response.status().as_u16()).into(),
                    );
                }
            }
            Err(err) => {
                return Err(format!("Get file request failed: {}", err).into());
            }
        }
    }
}
