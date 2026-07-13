use bytes::Bytes;
use http::Uri;
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client as HyperClient;
use log::{debug, error};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::fs;
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::GenericResult;
use crate::tcp::TcpTlsConnector;
use crate::tls::{Config, Protocol, ratls_client_config, tls_client_config};
use crate::vsock::VsockTlsConnector;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub enum ConnectorEnum
{
    Tcp(TcpTlsConnector),
    Vsock(VsockTlsConnector),
}

impl tower::Service<Uri> for ConnectorEnum
{
    type Response = hyper_util::rt::TokioIo<ConnectorStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>
    {
        match self {
            ConnectorEnum::Tcp(c) => c.poll_ready(cx),
            ConnectorEnum::Vsock(c) => c.poll_ready(cx),
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future
    {
        match self {
            ConnectorEnum::Tcp(connector) => {
                let mut connector = connector.clone();
                Box::pin(async move {
                    let io = connector.call(uri).await?;
                    Ok(hyper_util::rt::TokioIo::new(ConnectorStream::from_tcp(
                        io.into_inner(),
                    )))
                })
            }
            ConnectorEnum::Vsock(connector) => {
                let mut connector = connector.clone();
                Box::pin(async move {
                    let io = connector.call(uri).await?;
                    Ok(hyper_util::rt::TokioIo::new(ConnectorStream::from_vsock(
                        io.into_inner(),
                    )))
                })
            }
        }
    }
}

pub enum ConnectorStream
{
    Tcp(crate::tcp::TcpTlsStream),
    Vsock(crate::vsock::VsockTlsStream),
}

impl ConnectorStream
{
    fn from_tcp(stream: crate::tcp::TcpTlsStream) -> Self
    {
        ConnectorStream::Tcp(stream)
    }

    fn from_vsock(stream: crate::vsock::VsockTlsStream) -> Self
    {
        ConnectorStream::Vsock(stream)
    }
}

impl hyper_util::client::legacy::connect::Connection for ConnectorStream
{
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected
    {
        match self {
            ConnectorStream::Tcp(s) => s.connected(),
            ConnectorStream::Vsock(s) => s.connected(),
        }
    }
}

impl tokio::io::AsyncRead for ConnectorStream
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            ConnectorStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            ConnectorStream::Vsock(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for ConnectorStream
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>>
    {
        match self.get_mut() {
            ConnectorStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            ConnectorStream::Vsock(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            ConnectorStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            ConnectorStream::Vsock(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            ConnectorStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            ConnectorStream::Vsock(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

enum ResponseWrapper
{
    Tcp(hyper::Response<hyper::body::Incoming>),
    Vsock(hyper::Response<hyper::body::Incoming>),
}

impl ResponseWrapper
{
    fn content_type(&self) -> Option<String>
    {
        let headers = match self {
            ResponseWrapper::Tcp(r) => r.headers(),
            ResponseWrapper::Vsock(r) => r.headers(),
        };
        headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()))
    }

    fn content_length(&self) -> Option<usize>
    {
        let headers = match self {
            ResponseWrapper::Tcp(r) => r.headers(),
            ResponseWrapper::Vsock(r) => r.headers(),
        };
        headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|h| h.to_str().ok()?.parse().ok())
    }

    async fn stream_to_file(self, file: &mut fs::File) -> GenericResult<()>
    {
        let mut writer = BufWriter::new(file);
        let (_, mut body) = match self {
            ResponseWrapper::Tcp(r) => r.into_parts(),
            ResponseWrapper::Vsock(r) => r.into_parts(),
        };

        while let Some(frame_result) = body.frame().await {
            let frame = frame_result?;
            if let Ok(data) = frame.into_data() {
                writer.write_all(&data).await?;
            }
        }
        writer.flush().await?;
        Ok(())
    }

    async fn collect_bytes(self) -> GenericResult<Vec<u8>>
    {
        let body = match self {
            ResponseWrapper::Tcp(r) => r.into_body(),
            ResponseWrapper::Vsock(r) => r.into_body(),
        };
        let bytes = body.collect().await?.to_bytes();
        Ok(bytes.to_vec())
    }
}

pub struct Client
{
    connector: ConnectorEnum,
    protocol: &'static str,
}

impl Client
{
    pub async fn from_config(
        config: Config,
        vsock_cid: Option<u32>,
        vsock_port: Option<u32>,
    ) -> GenericResult<Self>
    {
        let protocol = match config.tls {
            Protocol::NoTLS => "http",
            Protocol::TLS | Protocol::RaTLS => "https",
        };

        let connector = if let (Some(cid), Some(port)) = (vsock_cid, vsock_port) {
            let tls_config = match config.tls {
                Protocol::NoTLS => None,
                Protocol::TLS => Some(tls_client_config(config)?),
                Protocol::RaTLS => Some(ratls_client_config(config)?),
            };
            let vsock_connector = VsockTlsConnector::new(tls_config, cid, port);
            ConnectorEnum::Vsock(vsock_connector)
        } else {
            let tls_config = match config.tls {
                Protocol::NoTLS => None,
                Protocol::TLS => Some(tls_client_config(config)?),
                Protocol::RaTLS => Some(ratls_client_config(config)?),
            };
            let tcp_connector = TcpTlsConnector::new(tls_config);
            ConnectorEnum::Tcp(tcp_connector)
        };

        Ok(Self {
            connector,
            protocol,
        })
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
        let content_type = response
            .content_type()
            .ok_or("Response doesn't contain Content-type")?;
        let content_length = response
            .content_length()
            .ok_or("Response doesn't contain Content-length")?;
        debug!(
            "Received response: Content-type: \"{}\"; Content-length: {}",
            content_type, content_length
        );

        response.stream_to_file(file).await?;
        Ok(content_length as u64)
    }

    fn build_client(&self) -> HyperClient<ConnectorEnum, Empty<Bytes>>
    {
        HyperClient::builder(hyper_util::rt::TokioExecutor::new()).build(self.connector.clone())
    }

    async fn get_response(&self, address: &str, skip: Option<u64>)
    -> GenericResult<ResponseWrapper>
    {
        // manually check if the protocol is already in the address, url doesn't do it
        let url = if address.contains("://") {
            let url = url::Url::parse(address)
                .inspect_err(|_| error!("Failed to parse URL: {}", address))?;
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
            let url = url::Url::parse(&url_string)
                .inspect_err(|_| error!("Failed to parse URL: {}", url_string))?;
            url.to_string()
        };

        let client = self.build_client();

        let mut req = http::Request::builder().method(http::Method::GET).uri(&url);
        if let Some(skip_bytes) = skip {
            req = req.header(
                http::header::RANGE.as_str(),
                format!("bytes={}-", skip_bytes),
            );
        }
        let req = req.body(Empty::<Bytes>::new())?;
        let response = client.request(req).await?;
        if !response.status().is_success() {
            return Err(format!("Response not successful: {}", response.status().as_u16()).into());
        }

        Ok(match &self.connector {
            ConnectorEnum::Tcp(_) => ResponseWrapper::Tcp(response),
            ConnectorEnum::Vsock(_) => ResponseWrapper::Vsock(response),
        })
    }

    async fn get(&self, address: &str, skip: Option<u64>)
    -> GenericResult<(Vec<u8>, String, usize)>
    {
        let response = self.get_response(address, skip).await?;
        let content_type = response
            .content_type()
            .ok_or("Response doesn't contain Content-type")?;
        let content_length = response
            .content_length()
            .ok_or("Response doesn't contain Content-length")?;
        let bytes = response.collect_bytes().await?;
        Ok((bytes, content_type, content_length))
    }
}
