#![allow(dead_code)]

mod client;
mod tcp;
mod tls;
mod token;
mod utils;
mod vsock;

pub type GenericResult<T> = Result<T, Box<dyn std::error::Error>>;

pub use client::Client;
pub use tls::Config as TlsConfig;
pub use tls::Protocol as TlsProtocol;
