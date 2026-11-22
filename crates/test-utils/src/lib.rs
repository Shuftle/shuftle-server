//! Helpers shared by the Shuftle server's tests.

use std::{
    convert::Infallible,
    fmt::Debug,
    future,
    net::SocketAddr,
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeyPair, KeySize},
    signature::KeyPair as _,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body::Body;
use http_body_util::Full;
use hyper::{Response, server::conn::http1, service::service_fn};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use jsonwebtoken::{
    Algorithm, EncodingKey, Header,
    jwk::{
        AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
        RSAKeyParameters, RSAKeyType,
    },
};
use pkcs8::PrivateKeyInfoRef;
use proptest::{
    strategy::Strategy,
    test_runner::{Config, TestCaseError, TestRunner},
};
use serde::Serialize;
use shuftle_server::config::{Auth, Cors};
use tokio::{net::TcpListener, runtime::Builder};
use url::Url;

/// Starts the server on a free port of this machine, refusing every browser page, and returns its
/// address. The server runs until the test's runtime shuts down.
///
/// # Errors
///
/// Returns the error that kept the server from listening.
pub async fn spawn_server() -> anyhow::Result<SocketAddr> {
    spawn_server_with_cors(Cors {
        allowed_origins: Vec::new(),
    })
    .await
}

/// Starts the server on a free port of this machine, allowing the browser pages `cors` allows, and
/// returns its address. The server runs until the test's runtime shuts down.
///
/// # Errors
///
/// Returns the error that kept the server from listening.
pub async fn spawn_server_with_cors(cors: Cors) -> anyhow::Result<SocketAddr> {
    let jwks_url = serve_keys(vec![TestKey::published()?.jwk.clone()]).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(shuftle_server::serve(
        listener,
        cors,
        test_auth(jwks_url)?,
        future::pending(),
    ));
    Ok(address)
}

/// Runs `future` to completion on a single-threaded runtime of its own, as `#[tokio::test]` does,
/// for property tests, whose bodies are synchronous.
///
/// # Errors
///
/// Fails the test case with the error that kept the runtime from starting or that `future`
/// returned.
pub fn block_on<T>(future: impl Future<Output = anyhow::Result<T>>) -> Result<T, TestCaseError> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| TestCaseError::fail(error.to_string()))?
        .block_on(future)
        .map_err(|error| TestCaseError::fail(format!("{error:#}")))
}

/// Checks `property` on cases from `strategy` against one server shared by every case, on a
/// single-threaded runtime of its own. `source` is the calling test's `file!()`, where proptest
/// records failing cases.
///
/// # Errors
///
/// Returns the error that kept the server from starting, or the failing case after shrinking.
pub fn check_against_server<S, F>(
    source: &'static str,
    strategy: &S,
    property: impl Fn(SocketAddr, S::Value) -> F,
) -> anyhow::Result<()>
where
    S: Strategy,
    S::Value: Debug,
    F: Future<Output = anyhow::Result<()>>,
{
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let address = runtime.block_on(spawn_server())?;
    let config = Config {
        source_file: Some(source),
        ..Config::default()
    };
    TestRunner::new(config)
        .run(strategy, |value| {
            runtime
                .block_on(property(address, value))
                .map_err(|error| TestCaseError::fail(format!("{error:#}")))
        })
        .map_err(|error| anyhow!("{error}"))
}

/// The content type of gRPC-Web requests and responses carrying protobuf.
pub const GRPC_WEB: &str = "application/grpc-web+proto";

/// A gRPC message frame holding an empty message: no compression flag, then a length of 0.
pub const EMPTY_MESSAGE: [u8; 5] = [0; 5];

/// An HTTP/2 client without TLS, sending raw requests as browsers and proxies do.
#[must_use]
pub fn http2_client<B>() -> Client<HttpConnector, B>
where
    B: Body + Send,
    B::Data: Send,
{
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(connector)
}

/// The issuer of the test identity provider.
const ISSUER: &str = "https://keycloak.test/realms/shuftle";

/// The audience the test server expects.
const AUDIENCE: &str = "shuftle-server";

/// How long test tokens stay valid.
const TOKEN_LIFETIME: Duration = Duration::from_hours(1);

/// The identity provider the test server trusts, publishing its keys at `jwks_url`.
///
/// # Errors
///
/// Returns the error that kept the settings from being built.
fn test_auth(jwks_url: Url) -> anyhow::Result<Auth> {
    Ok(Auth {
        issuer: Url::parse(ISSUER)?,
        audience: AUDIENCE.to_owned(),
        jwks_url,
    })
}

/// A signing key of the test identity provider, generated once per test binary.
pub struct TestKey {
    /// The private half, signing tokens.
    encoding: EncodingKey,
    /// The public half, as the identity provider publishes it.
    jwk: Jwk,
}

/// The test identity provider's keys, generated on first use: one it publishes, one it does not.
static KEYS: LazyLock<Result<[TestKey; 2], String>> = LazyLock::new(|| {
    Ok([
        TestKey::generate("published").map_err(|error| format!("{error:#}"))?,
        TestKey::generate("unpublished").map_err(|error| format!("{error:#}"))?,
    ])
});

impl TestKey {
    /// The key the test identity provider publishes.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the keys from being generated.
    pub fn published() -> anyhow::Result<&'static Self> {
        let [published, _] = KEYS.as_ref().map_err(|error| anyhow!("{error}"))?;
        Ok(published)
    }

    /// A key the test identity provider does not publish.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the keys from being generated.
    pub fn unpublished() -> anyhow::Result<&'static Self> {
        let [_, unpublished] = KEYS.as_ref().map_err(|error| anyhow!("{error}"))?;
        Ok(unpublished)
    }

    /// Generates an RSA key named `kid` for RS256, as Keycloak signs by default. jsonwebtoken takes
    /// the PKCS#1 key, which aws-lc-rs exports wrapped in PKCS#8.
    fn generate(kid: &str) -> anyhow::Result<Self> {
        let pair = KeyPair::generate(KeySize::Rsa2048).map_err(|_| anyhow!("generating {kid}"))?;
        let der = pair.as_der().map_err(|_| anyhow!("encoding {kid}"))?;
        let public = pair.public_key();
        let base64url = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::RS256),
                key_id: Some(kid.to_owned()),
                ..CommonParameters::default()
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: base64url(public.modulus().big_endian_without_leading_zero()),
                e: base64url(public.exponent().big_endian_without_leading_zero()),
            }),
        };
        let pkcs8 = PrivateKeyInfoRef::try_from(der.as_ref())
            .map_err(|error| anyhow!("unwrapping {kid} from PKCS#8: {error}"))?;
        Ok(Self {
            encoding: EncodingKey::from_rsa_der(pkcs8.private_key.as_bytes()),
            jwk,
        })
    }

    /// Signs `claims` as RS256, naming this key in the header.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the token from being signed.
    pub fn sign(&self, claims: &Claims) -> anyhow::Result<String> {
        self.sign_naming(self, claims)
    }

    /// Signs `claims` as RS256 with this key, naming `named` in the header.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the token from being signed.
    pub fn sign_naming(&self, named: &Self, claims: &Claims) -> anyhow::Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid.clone_from(&named.jwk.common.key_id);
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding)?)
    }
}

/// The claims of a test access token.
#[derive(Debug, Clone, Serialize)]
pub struct Claims {
    /// The issuer.
    pub iss: String,
    /// The audience.
    pub aud: String,
    /// The subject: the player's id at the identity provider.
    pub sub: String,
    /// When the token expires, in seconds since the Unix epoch.
    pub exp: u64,
}

impl Claims {
    /// Claims the test server accepts, for the player `sub`.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the current time from being read.
    pub fn valid(sub: &str) -> anyhow::Result<Self> {
        let expiry = SystemTime::now().duration_since(UNIX_EPOCH)? + TOKEN_LIFETIME;
        Ok(Self {
            iss: ISSUER.to_owned(),
            aud: AUDIENCE.to_owned(),
            sub: sub.to_owned(),
            exp: expiry.as_secs(),
        })
    }
}

/// Publishes `keys` as a JWK Set on a free port of this machine, standing in for the identity
/// provider, until the test's runtime shuts down. Returns where the keys are published.
///
/// # Errors
///
/// Returns the error that kept the keys from being encoded or the server from listening.
async fn serve_keys(keys: Vec<Jwk>) -> anyhow::Result<Url> {
    let body = Bytes::from(serde_json::to_vec(&JwkSet { keys })?);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = Url::parse(&format!("http://{}/jwks", listener.local_addr()?))?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let body = body.clone();
            let service = service_fn(move |_request| {
                let response = Response::new(Full::new(body.clone()));
                async move { Ok::<_, Infallible>(response) }
            });
            tokio::spawn(http1::Builder::new().serve_connection(TokioIo::new(stream), service));
        }
    });
    Ok(url)
}
