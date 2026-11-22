//! The server's configuration, read from a TOML file.

use std::{net::SocketAddr, str::FromStr};

use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Everything the server needs to know about its deployment.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the server listens.
    pub listen: SocketAddr,
    /// Which browser pages may call the server.
    pub cors: Cors,
}

impl FromStr for Config {
    type Err = toml::de::Error;

    fn from_str(toml: &str) -> Result<Self, Self::Err> {
        toml::from_str(toml)
    }
}

/// Cross-origin access for browsers.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cors {
    /// The pages whose scripts may call the server. Empty refuses every browser page.
    pub allowed_origins: Vec<AllowedOrigin>,
}

/// A web origin, written exactly as browsers send it in the `Origin` header.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct AllowedOrigin(String);

impl TryFrom<String> for AllowedOrigin {
    type Error = NotAnOrigin;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        match Self::check(&input) {
            Ok(()) => Ok(Self(input)),
            Err(reason) => Err(NotAnOrigin { input, reason }),
        }
    }
}

impl AllowedOrigin {
    /// Checks that `input` is exactly the origin of the http or https URL it spells.
    fn check(input: &str) -> Result<(), Reason> {
        let url = HttpUrl::try_from(Url::parse(input).map_err(Reason::Unparsable)?)?;
        let expected = url.origin();
        if input == expected {
            Ok(())
        } else {
            Err(Reason::NotCanonical { expected })
        }
    }
}

/// A URL whose scheme is http or https, so its origin is a scheme, a host and a port.
struct HttpUrl(Url);

impl TryFrom<Url> for HttpUrl {
    type Error = Reason;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        match url.scheme() {
            "http" | "https" => Ok(Self(url)),
            _ => Err(Reason::UnsupportedScheme),
        }
    }
}

impl HttpUrl {
    /// The origin, written as browsers send it in the `Origin` header.
    fn origin(&self) -> String {
        self.0.origin().ascii_serialization()
    }
}

/// A configured origin is not written exactly as browsers send it.
#[derive(Debug, Error)]
#[error("`{input}` is not an origin: {reason}")]
pub struct NotAnOrigin {
    input: String,
    reason: Reason,
}

/// Why a configured origin was refused.
#[derive(Debug, Error)]
enum Reason {
    #[error(transparent)]
    Unparsable(url::ParseError),
    #[error("the scheme must be http or https")]
    UnsupportedScheme,
    #[error("did you mean `{expected}`?")]
    NotCanonical { expected: String },
}
