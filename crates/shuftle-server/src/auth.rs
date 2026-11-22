//! Authentication: every call outside the public ones must carry a valid access token.

use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use anyhow::{Context as _, anyhow};
use headers::{Authorization, HeaderMapExt, authorization::Bearer};
use http::{HeaderMap, Request, Response};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet},
};
use serde::de::IgnoredAny;
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
    validation: Arc<Validation>,
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
            validation: Arc::new(validation(auth)),
        })
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = Authenticated<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Authenticated {
            inner,
            keys: Arc::clone(&self.keys),
            validation: Arc::clone(&self.validation),
        }
    }
}

/// The service behind [`AuthLayer`].
#[derive(Debug, Clone)]
pub struct Authenticated<S> {
    inner: S,
    keys: Arc<SigningKeys>,
    validation: Arc<Validation>,
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
        let validation = Arc::clone(&self.validation);
        Box::pin(async move {
            if is_public(request.uri().path()) {
                return inner.call(request).await;
            }
            match authenticate(&keys, &validation, request.headers()).await {
                Ok(()) => inner.call(request).await,
                Err(refusal) => Ok(refusal.into_status().into_http()),
            }
        })
    }
}

/// The checks a token from the identity provider `auth` describes must pass.
fn validation(auth: &Auth) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&auth.issuer]);
    validation.set_audience(&[&auth.audience]);
    validation
}

/// Checks the access token in `headers` against `validation`.
async fn authenticate(
    keys: &SigningKeys,
    validation: &Validation,
    headers: &HeaderMap,
) -> Result<(), Refusal> {
    let Authorization(bearer) = headers
        .typed_try_get::<Authorization<Bearer>>()
        .context("authorization is not a Bearer token")
        .map_err(Refusal::Unauthenticated)?
        .ok_or_else(|| Refusal::Unauthenticated(anyhow!("missing authorization metadata")))?;
    let header = decode_header(bearer.token())
        .context("malformed token")
        .map_err(Refusal::Unauthenticated)?;
    let kid = header
        .kid
        .ok_or_else(|| Refusal::Unauthenticated(anyhow!("the token names no signing key")))?;
    let jwk = keys
        .find(&kid)
        .await?
        .ok_or_else(|| Refusal::Unauthenticated(anyhow!("unknown signing key {kid}")))?;
    let key = DecodingKey::from_jwk(&jwk)
        .with_context(|| format!("unusable signing key {kid}"))
        .map_err(Refusal::Unavailable)?;
    decode::<IgnoredAny>(bearer.token(), &key, validation)
        .with_context(|| format!("verifying the token signed by key {kid}"))
        .map_err(Refusal::Unauthenticated)?;
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
    async fn find(&self, kid: &str) -> Result<Option<Jwk>, Refusal> {
        let cached = self
            .cached
            .read()
            .map_err(|error| Refusal::Internal(anyhow!("reading the key cache: {error}")))?
            .find(kid)
            .cloned();
        if cached.is_some() {
            return Ok(cached);
        }
        let fresh = self
            .fetch()
            .await
            .with_context(|| format!("fetching the signing keys from {}", self.url))
            .map_err(Refusal::Unavailable)?;
        let found = fresh.find(kid).cloned();
        *self
            .cached
            .write()
            .map_err(|error| Refusal::Internal(anyhow!("writing the key cache: {error}")))? = fresh;
        Ok(found)
    }

    /// The key set the identity provider publishes now.
    async fn fetch(&self) -> anyhow::Result<JwkSet> {
        Ok(self
            .client
            .get(self.url.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

/// Why a call did not reach its service: one variant per thing the caller must do. Each carries
/// the chain of causes.
#[derive(Debug, Error)]
enum Refusal {
    /// The caller must sign in again.
    #[error("invalid access token, sign in again")]
    Unauthenticated(#[source] anyhow::Error),
    /// The caller may retry later.
    #[error("cannot verify access tokens right now, retry later")]
    Unavailable(#[source] anyhow::Error),
    /// A server bug the caller cannot act on.
    #[error("internal server error")]
    Internal(#[source] anyhow::Error),
}

impl Refusal {
    /// The gRPC status telling the caller what to do.
    fn into_status(self) -> Status {
        let message = self.to_string();
        match self {
            Self::Unauthenticated(_) => Status::unauthenticated(message),
            Self::Unavailable(_) => Status::unavailable(message),
            Self::Internal(_) => Status::internal(message),
        }
    }
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
