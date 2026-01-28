use std::error::Error;
use std::fmt::Display;
use std::string::FromUtf8Error;
use base64::DecodeError;
use rust_rsi::TokenError;
use rustls::pki_types::InvalidDnsNameError;
use x509_certificate::X509CertificateError;

#[derive(Debug)]
pub enum RaTlsError {
    IOError(std::io::Error),
    RustlsError(rustls::Error),
    InvalidDnsName(InvalidDnsNameError),
    SinglePrivateKeyIsRequired,
    PrivateKeyParsingError(String),
    InvalidCCAToken,
    RsaError(rsa::Error),
    Utf8DecodingError(FromUtf8Error),
    Base64DecodeError(DecodeError),
    Pkcs8Error(pkcs8::Error),
    Pkcs8SpkiError(pkcs8::spki::Error),
    RcgenError(rcgen::Error),
    Asn1DecodeError(simple_asn1::ASN1DecodeErr),
    Asn1EncodeError(simple_asn1::ASN1EncodeErr),
    CertParsingError(X509CertificateError),
    MissingTokenInCertificate,
    CannotExtractTokenFromExtension,
    RustRsiTokenError(TokenError),
    InvalidChallenge,
    HandshakeError,
    PkcsDERError(pkcs8::der::Error),

    GenericTokenResolverError(Box<dyn std::error::Error + Sync + Send>),
    GenericTokenVerifierError(Box<dyn std::error::Error + Sync + Send>)
}

impl From<std::io::Error> for RaTlsError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}

impl From<rustls::Error> for RaTlsError {
    fn from(value: rustls::Error) -> Self {
        Self::RustlsError(value)
    }
}

impl From<InvalidDnsNameError> for RaTlsError {
    fn from(value: InvalidDnsNameError) -> Self {
        Self::InvalidDnsName(value)
    }
}

impl From<rsa::Error> for RaTlsError {
    fn from(value: rsa::Error) -> Self {
        Self::RsaError(value)
    }
}

impl From<FromUtf8Error> for RaTlsError {
    fn from(value: FromUtf8Error) -> Self {
        Self::Utf8DecodingError(value)
    }
}

impl From<DecodeError> for RaTlsError {
    fn from(value: DecodeError) -> Self {
        Self::Base64DecodeError(value)
    }
}

impl From<pkcs8::Error> for RaTlsError {
    fn from(value: pkcs8::Error) -> Self {
        Self::Pkcs8Error(value)
    }
}

impl From<pkcs8::spki::Error> for RaTlsError {
    fn from(value: pkcs8::spki::Error) -> Self {
        Self::Pkcs8SpkiError(value)
    }
}

impl From<rcgen::Error> for RaTlsError {
    fn from(value: rcgen::Error) -> Self {
        Self::RcgenError(value)
    }
}

impl From<simple_asn1::ASN1DecodeErr> for RaTlsError {
    fn from(value: simple_asn1::ASN1DecodeErr) -> Self {
        Self::Asn1DecodeError(value)
    }
}

impl From<simple_asn1::ASN1EncodeErr> for RaTlsError {
    fn from(value: simple_asn1::ASN1EncodeErr) -> Self {
        Self::Asn1EncodeError(value)
    }
}

impl From<X509CertificateError> for RaTlsError {
    fn from(value: X509CertificateError) -> Self {
        Self::CertParsingError(value)
    }
}

impl From<TokenError> for RaTlsError {
    fn from(value: TokenError) -> Self {
        Self::RustRsiTokenError(value)
    }
}

impl From<pkcs8::der::Error> for RaTlsError {
    fn from(value: pkcs8::der::Error) -> Self {
        Self::PkcsDERError(value)
    }
}

impl Error for RaTlsError {}

impl Display for RaTlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
