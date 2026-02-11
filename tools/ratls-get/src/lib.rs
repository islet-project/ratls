#![allow(dead_code)]

mod client;
mod tls;
mod token;

pub type GenericResult<T> = Result<T, Box<dyn std::error::Error>>;

pub use client::Client;
pub use tls::Config as TlsConfig;
pub use tls::Protocol as TlsProtocol;
