use http::Uri;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, pki_types::ServerName};
use tower::Service;

#[derive(Clone)]
pub struct TcpTlsConnector
{
    tls_config: Option<Arc<ClientConfig>>,
}

impl TcpTlsConnector
{
    pub fn new(tls_config: Option<ClientConfig>) -> Self
    {
        Self {
            tls_config: tls_config.map(Arc::new),
        }
    }
}

pub enum TcpTlsStream
{
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl hyper_util::client::legacy::connect::Connection for TcpTlsStream
{
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected
    {
        match self {
            TcpTlsStream::Plain(stream) => stream.connected(),
            TcpTlsStream::Tls(tls_stream) => {
                let (tcp_stream, _) = tls_stream.get_ref();
                tcp_stream.connected()
            }
        }
    }
}

impl AsyncRead for TcpTlsStream
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            TcpTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            TcpTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TcpTlsStream
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>>
    {
        match self.get_mut() {
            TcpTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            TcpTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            TcpTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            TcpTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    {
        match self.get_mut() {
            TcpTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            TcpTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Service<Uri> for TcpTlsConnector
{
    type Response = TokioIo<TcpTlsStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>
    {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future
    {
        let tls_config = self.tls_config.clone();

        Box::pin(async move {
            let host = uri.host().ok_or_else(|| "Missing host in URI")?;
            let port = uri.port_u16().unwrap_or(80);
            let addr = format!("{}:{}", host, port);

            let stream = TcpStream::connect(addr).await?;

            if uri.scheme_str() == Some("https") {
                if let Some(config) = tls_config {
                    let connector = TlsConnector::from(config);
                    let domain = ServerName::try_from(host.to_string())
                        .map_err(|_| "Invalid domain name")?
                        .to_owned();

                    let tls_stream = connector.connect(domain, stream).await?;
                    Ok(TokioIo::new(TcpTlsStream::Tls(tls_stream)))
                } else {
                    Err("HTTPS requested but no TLS config provided".into())
                }
            } else {
                Ok(TokioIo::new(TcpTlsStream::Plain(stream)))
            }
        })
    }
}
