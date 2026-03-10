use log::{debug, error};
use reqwest::blocking::{Client as ReqwestClient, Response};
use reqwest::{Url, header};
use std::fs;

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
            Protocol::NoTLS => "http",
            Protocol::TLS | Protocol::RaTLS => "https",
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

    /// Handle simplified listing request case that doesn't save any file
    pub fn list_dir(&self, url: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>>
    {
        let (response, content_type, content_length) = self.get(url, None)?;
        debug!(
            "Received response: Content-type: \"{}\"; Content-length: {}",
            content_type, content_length
        );

        Ok(response.json()?)
    }

    /// Actually perform the HTTP request and download the file
    pub fn download_file(
        &self,
        url: &str,
        file: &mut fs::File,
        skip: Option<u64>,
    ) -> Result<u64, Box<dyn std::error::Error>>
    {
        let (mut response, content_type, content_length) = self.get(url, skip)?;
        debug!(
            "Received response: Content-type: \"{}\"; Content-length: {}",
            content_type, content_length
        );

        std::io::copy(&mut response, file)?;
        Ok(content_length as u64)
    }

    // the response needs to contain length and type, it's an error if it doesn't
    fn get(&self, address: &str, skip: Option<u64>) -> GenericResult<(Response, String, usize)>
    {
        // manually check if the protocol is already in the address, url doesn't do it
        let url = if address.contains("://") {
            let url =
                Url::parse(address).inspect_err(|_| error!("Failed to parse URL: {}", address))?;
            if url.scheme() != self.protocol {
                return Err(format!(
                    "Wrong protocol for the TLS type, got: {}, expected: {}",
                    url.scheme(),
                    self.protocol
                )
                .into());
            }
            url.to_string()
        } else {
            let url_string = &format!("{}://{}", self.protocol, address);
            let url = Url::parse(&url_string)
                .inspect_err(|_| error!("Failed to parse URL: {}", url_string))?;
            url.to_string()
        };

        let request = self.reqwest.get(&url);
        let request = if let Some(skip_bytes) = skip {
            request.header(header::RANGE, format!("bytes={}-", skip_bytes))
        } else {
            request
        };

        match request.send() {
            Ok(response) => {
                if response.status().is_success() {
                    let headers = response.headers();
                    let content_type = match utils::content_type(headers) {
                        Some(ct) => ct,
                        None => return Err("Response doesn't contain Content-type".into()),
                    };
                    let content_length = match utils::content_length(headers) {
                        Some(cl) => cl,
                        None => return Err("Response doesn't contain Content-length".into()),
                    };
                    Ok((response, content_type, content_length))
                } else {
                    Err(format!("Response not successful: {}", response.status().as_u16()).into())
                }
            }
            Err(err) => {
                error!("Reqwest request failed: {}", err);
                Err(Box::new(err))
            }
        }
    }
}
