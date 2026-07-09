use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client as HyperClient;
use log::{debug, error};
use reqwest::{Client as ReqwestClient, Url, header};
use tokio::fs;
use tokio::io::{AsyncWriteExt, BufWriter};
use futures_util::StreamExt;

use crate::tls::{Config, Protocol, ratls_client_config, tls_client_config};
use crate::vsock::VsockTlsConnector;
use crate::GenericResult;

enum ResponseWrapper
{
    Reqwest(reqwest::Response),
    Hyper(hyper::Response<hyper::body::Incoming>),
}

impl ResponseWrapper
{
    fn content_type(&self) -> Option<String>
    {
        match self {
            ResponseWrapper::Reqwest(r) => r.headers().get(header::CONTENT_TYPE)?.to_str().ok().map(|s| s.to_string()),
            ResponseWrapper::Hyper(r) => r.headers().get(header::CONTENT_TYPE)?.to_str().ok().map(|s| s.to_string()),
        }
    }

    fn content_length(&self) -> Option<usize>
    {
        match self {
            ResponseWrapper::Reqwest(r) => r.headers().get(header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok(),
            ResponseWrapper::Hyper(r) => r.headers().get(header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok(),
        }
    }

    async fn stream_to_file(self, file: &mut fs::File) -> GenericResult<()>
    {
        let mut writer = BufWriter::new(file);
        match self {
            ResponseWrapper::Reqwest(r) => {
                let mut stream = r.bytes_stream();
                while let Some(chunk_result) = stream.next().await {
                    let chunk = chunk_result?;
                    writer.write_all(&chunk).await?;
                }
            }
            ResponseWrapper::Hyper(r) => {
                let (_, mut body) = r.into_parts();
                while let Some(frame_result) = body.frame().await {
                    let frame = frame_result?;
                    match frame.into_data() {
                        Ok(data) => writer.write_all(&data).await?,
                        Err(_) => {}
                    }
                }
            }
        }
        writer.flush().await?;
        Ok(())
    }

    async fn collect_bytes(self) -> GenericResult<Vec<u8>>
    {
        match self {
            ResponseWrapper::Reqwest(r) => Ok(r.bytes().await?.to_vec()),
            ResponseWrapper::Hyper(r) => {
                let (_, body) = r.into_parts();
                let bytes = body.collect().await?.to_bytes();
                Ok(bytes.to_vec())
            }
        }
    }
}

enum BackendClient
{
    Reqwest(ReqwestClient),
    Hyper(HyperClient<VsockTlsConnector, Empty<Bytes>>),
}


pub struct Client
{
    backend: BackendClient,
    protocol: &'static str,
}

impl Client
{
    pub async fn from_config(config: Config, vsock_cid: Option<u32>, vsock_port: Option<u32>) -> GenericResult<Self>
    {
        let protocol = match config.tls {
            Protocol::NoTLS => "http",
            Protocol::TLS | Protocol::RaTLS => "https",
        };

         if let (Some(cid), Some(port)) = (vsock_cid, vsock_port) {
            let tls_config = match config.tls {
                Protocol::NoTLS => None,
                Protocol::TLS => Some(tls_client_config(config)?),
                Protocol::RaTLS => Some(ratls_client_config(config)?),
            };
            let connector = VsockTlsConnector::new(tls_config, cid, port);
            let hyper =
                hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                    .build(connector);
            return Ok(Self {
                backend: BackendClient::Hyper(hyper),
                protocol,
            });
        }

        let reqwest = match config.tls {
            Protocol::NoTLS => ReqwestClient::new(),
            Protocol::TLS => ReqwestClient::builder()
                .use_preconfigured_tls(tls_client_config(config)?)
                .build()?,
            Protocol::RaTLS => ReqwestClient::builder()
                .use_preconfigured_tls(ratls_client_config(config)?)
                .build()?,
        };

        Ok(Self { backend: BackendClient::Reqwest(reqwest), protocol })
    }

    /// Handle simplified listing request case that doesn't save any file
    pub async fn list_dir(&self, url: &str) -> GenericResult<serde_json::Value>
    {
        let (bytes, content_type, content_length) = self.get(url, None).await?;
        debug!(
            "Received response: Content-type: \"{}\"; Content-length: {}",
            content_type, content_length
        );

        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Actually perform the HTTP request and download the file
    pub async fn download_file(
        &self,
        url: &str,
        file: &mut fs::File,
        skip: Option<u64>,
    ) -> GenericResult<u64>
    {
        let response = self.get_response(url, skip).await?;
        let content_type = response.content_type().ok_or("Response doesn't contain Content-type")?;
        let content_length = response.content_length().ok_or("Response doesn't contain Content-length")?;
        debug!(
            "Received response: Content-type: \"{}\"; Content-length: {}",
            content_type, content_length
        );

        response.stream_to_file(file).await?;
        Ok(content_length as u64)
    }

    async fn get_response(&self, address: &str, skip: Option<u64>) -> GenericResult<ResponseWrapper>
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

        match &self.backend {
            BackendClient::Reqwest(client) => {
                let request = client.get(&url);
                let request = if let Some(skip_bytes) = skip {
                    request.header(header::RANGE, format!("bytes={}-", skip_bytes))
                } else {
                    request
                };

                let response = request.send().await?;
                if !response.status().is_success() {
                    return Err(
                        format!("Response not successful: {}", response.status().as_u16()).into(),
                    );
                }
                Ok(ResponseWrapper::Reqwest(response))
            }
            BackendClient::Hyper(client) => {
                let mut req = http::Request::builder()
                    .method(http::Method::GET)
                    .uri(&url);
                if let Some(skip_bytes) = skip {
                    req = req.header(header::RANGE.as_str(), format!("bytes={}-", skip_bytes));
                }
                let req = req.body(Empty::<Bytes>::new())?;
                let response = client.request(req).await?;
                if !response.status().is_success() {
                    return Err(
                        format!("Response not successful: {}", response.status().as_u16()).into(),
                    );
                }
                Ok(ResponseWrapper::Hyper(response))
            }
        }
    }

    async fn get(&self, address: &str, skip: Option<u64>) -> GenericResult<(Vec<u8>, String, usize)>
    {
        let response = self.get_response(address, skip).await?;
        let content_type = response.content_type().ok_or("Response doesn't contain Content-type")?;
        let content_length = response.content_length().ok_or("Response doesn't contain Content-length")?;
        let bytes = response.collect_bytes().await?;
        Ok((bytes, content_type, content_length))
    }
}
