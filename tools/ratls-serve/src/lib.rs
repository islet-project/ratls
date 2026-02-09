mod files;
mod httpd;

pub type GenericResult<T> = Result<T, Box<dyn std::error::Error>>;

pub use files::SimpleFiles;
pub use httpd::run as httpd_run;
