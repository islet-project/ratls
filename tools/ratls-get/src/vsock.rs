use http::Uri;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, pki_types::ServerName};
use tokio_vsock::{VsockAddr, VsockStream};
use tower::Service;

use crate::conproto;

#[derive(Clone)]
pub struct VsockTlsConnector
{
    tls_config: Option<Arc<ClientConfig>>,
    vsock_cid: u32,
    vsock_port: u32,
    conproto: bool,
}

impl VsockTlsConnector
{
    pub fn new(
        tls_config: Option<ClientConfig>,
        vsock_cid: u32,
        vsock_port: u32,
        conproto: bool,
    ) -> Self
    {
        Self {
            tls_config: tls_config.map(Arc::new),
            vsock_cid,
            vsock_port,
            conproto,
        }
    }
}

pub enum VsockTlsStream
{
    Plain(VsockStream),
    Tls(tokio_rustls::client::TlsStream<VsockStream>),
}

impl hyper_util::client::legacy::connect::Connection for VsockTlsStream
{
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected
    {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl AsyncRead for VsockTlsStream
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            VsockTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            VsockTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VsockTlsStream
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>>
    {
        match self.get_mut() {
            VsockTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            VsockTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            VsockTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            VsockTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            VsockTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            VsockTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Service<Uri> for VsockTlsConnector
{
    type Response = TokioIo<VsockTlsStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>
    {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future
    {
        let cid = self.vsock_cid;
        let port = self.vsock_port;
        let tls_config = self.tls_config.clone();
        let conproto = self.conproto;

        Box::pin(async move {
            let addr = VsockAddr::new(cid, port);
            let mut stream = VsockStream::connect(addr).await?;

            // Extract hostname for TLS verification (always needed for HTTPS)
            let hostname = uri.host().ok_or_else(|| "Missing host in URI")?;

            if conproto {
                let dest_port = uri
                    .port_u16()
                    .unwrap_or(if uri.scheme_str() == Some("https") {
                        443
                    } else {
                        80
                    });

                conproto::connect(&mut stream, hostname, dest_port).await?;
            }

            if uri.scheme_str() == Some("https") {
                if let Some(config) = tls_config {
                    let connector = TlsConnector::from(config);
                    let domain = ServerName::try_from(hostname.to_string())
                        .map_err(|_| "Invalid domain name")?
                        .to_owned();

                    let tls_stream = connector.connect(domain, stream).await?;
                    Ok(TokioIo::new(VsockTlsStream::Tls(tls_stream)))
                } else {
                    Err("HTTPS requested but no TLS config provided".into())
                }
            } else {
                Ok(TokioIo::new(VsockTlsStream::Plain(stream)))
            }
        })
    }
}
