mod files;
mod httpd;
mod tls;
mod utils;

pub type GenericResult<T> = Result<T, Box<dyn std::error::Error>>;

pub use files::SimpleFiles;
pub use httpd::run as httpd_run;
pub use tls::Config as TlsConfig;
pub use tls::Protocol as TlsProtocol;
