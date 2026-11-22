//! Authentication: every call outside the public ones must carry a valid access token.

use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use anyhow::anyhow;
use headers::{Authorization, HeaderMapExt, authorization::Bearer};
use http::{HeaderMap, Request, Response};
use jsonwebtoken::{
    decode_header,
    jwk::{Jwk, JwkSet},
};
use thiserror::Error;
use tonic::Status;
use tower_layer::Layer;
use tower_service::Service;
use url::Url;

use crate::config::Auth;

/// The services anyone may call without a token.
const PUBLIC_SERVICES: [&str; 1] = ["shuftle.version.v1.VersionService"];

/// The reflection service, public in development builds for tools such as grpcurl.
const REFLECTION_SERVICE: &str = "grpc.reflection.v1.ServerReflection";

/// Refuses calls without a valid access token from the configured identity provider.
#[derive(Debug, Clone)]
pub struct AuthLayer {
    keys: Arc<SigningKeys>,
}

impl AuthLayer {
    /// A layer accepting the tokens `auth` describes.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the HTTP client for fetching signing keys from being built.
    pub fn new(auth: &Auth) -> anyhow::Result<Self> {
        Ok(Self {
            keys: Arc::new(SigningKeys {
                url: auth.jwks_url.clone(),
                client: reqwest::Client::builder().build()?,
                cached: RwLock::new(JwkSet { keys: Vec::new() }),
            }),
        })
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = Authenticated<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Authenticated {
            inner,
            keys: Arc::clone(&self.keys),
        }
    }
}

/// The service behind [`AuthLayer`].
#[derive(Debug, Clone)]
pub struct Authenticated<S> {
    inner: S,
    keys: Arc<SigningKeys>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Authenticated<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // The ready inner service handles this call; a fresh clone waits for the next one.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let keys = Arc::clone(&self.keys);
        Box::pin(async move {
            if is_public(request.uri().path()) {
                return inner.call(request).await;
            }
            match authenticate(&keys, request.headers()).await {
                Ok(()) => inner.call(request).await,
                Err(refusal) => Ok(refusal.into_status().into_http()),
            }
        })
    }
}

/// Checks the access token in `headers`.
async fn authenticate(keys: &SigningKeys, headers: &HeaderMap) -> Result<(), Refusal> {
    let Authorization(bearer) = match headers.typed_try_get::<Authorization<Bearer>>() {
        Ok(Some(authorization)) => authorization,
        Ok(None) => return Err(Rejection::Missing.into()),
        Err(_) => return Err(Rejection::NotBearer.into()),
    };
    let header = decode_header(bearer.token()).map_err(|_| Rejection::Malformed)?;
    let kid = header.kid.ok_or(Rejection::NoKeyId)?;
    keys.find(&kid).await?.ok_or(Rejection::UnknownKey)?;
    Ok(())
}

/// The identity provider's signing keys, fetched from its JWK Set and refreshed when a token names
/// a key not seen yet.
#[derive(Debug)]
struct SigningKeys {
    url: Url,
    client: reqwest::Client,
    cached: RwLock<JwkSet>,
}

impl SigningKeys {
    /// The key named `kid`, refetching the key set when it is not cached.
    async fn find(&self, kid: &str) -> anyhow::Result<Option<Jwk>> {
        let cached = self
            .cached
            .read()
            .map_err(|error| anyhow!("{error}"))?
            .find(kid)
            .cloned();
        if cached.is_some() {
            return Ok(cached);
        }
        let fresh: JwkSet = self
            .client
            .get(self.url.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let found = fresh.find(kid).cloned();
        *self.cached.write().map_err(|error| anyhow!("{error}"))? = fresh;
        Ok(found)
    }
}

/// Why a call did not reach its service.
#[derive(Debug, Error)]
enum Refusal {
    #[error(transparent)]
    Rejected(#[from] Rejection),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Refusal {
    /// The gRPC status telling the caller why.
    fn into_status(self) -> Status {
        match self {
            Self::Rejected(rejection) => Status::unauthenticated(rejection.to_string()),
            Self::Other(_) => {
                Status::unavailable("the identity provider's signing keys are unavailable")
            }
        }
    }
}

/// Why a token was refused.
#[derive(Debug, Error)]
enum Rejection {
    #[error("missing authorization metadata")]
    Missing,
    #[error("authorization is not a Bearer token")]
    NotBearer,
    #[error("malformed token")]
    Malformed,
    #[error("the token names no signing key")]
    NoKeyId,
    #[error("unknown signing key")]
    UnknownKey,
}

/// Whether the call at `path` needs no token.
fn is_public(path: &str) -> bool {
    let service = path
        .strip_prefix('/')
        .and_then(|path| path.split_once('/'))
        .map(|(service, _method)| service);
    service.is_some_and(|service| {
        PUBLIC_SERVICES.contains(&service)
            || (cfg!(feature = "dev") && service == REFLECTION_SERVICE)
    })
}
