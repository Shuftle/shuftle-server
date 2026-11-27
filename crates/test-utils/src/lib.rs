//! Helpers shared by the Shuftle server's tests.

use std::{
    fmt::Debug,
    future,
    net::SocketAddr,
    sync::{
        Arc, LazyLock, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
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
use hyper::{Response, StatusCode, server::conn::http1, service::service_fn};
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
    spawn_server_with_keys(KeyServer::start(&[TestKey::published()?]).await?.url()).await
}

/// Starts the server on a free port of this machine, allowing the browser pages `cors` allows, and
/// returns its address. The server runs until the test's runtime shuts down.
///
/// # Errors
///
/// Returns the error that kept the server from listening.
pub async fn spawn_server_with_cors(cors: Cors) -> anyhow::Result<SocketAddr> {
    let keys = KeyServer::start(&[TestKey::published()?]).await?;
    spawn(cors, keys.url().clone()).await
}

/// Starts the server on a free port of this machine, trusting the keys published at `jwks_url`,
/// and returns its address. The server runs until the test's runtime shuts down.
///
/// # Errors
///
/// Returns the error that kept the server from listening.
pub async fn spawn_server_with_keys(jwks_url: &Url) -> anyhow::Result<SocketAddr> {
    spawn(
        Cors {
            allowed_origins: Vec::new(),
        },
        jwks_url.clone(),
    )
    .await
}

/// Starts the server on a free port of this machine with `cors`, trusting the keys published at
/// `jwks_url`, and returns its address.
async fn spawn(cors: Cors, jwks_url: Url) -> anyhow::Result<SocketAddr> {
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

/// The test identity provider's keys, generated on first use: one it publishes, one it does not,
/// and one it publishes later.
static KEYS: LazyLock<Result<[TestKey; 3], String>> = LazyLock::new(|| {
    Ok([
        TestKey::generate("published").map_err(|error| format!("{error:#}"))?,
        TestKey::generate("unpublished").map_err(|error| format!("{error:#}"))?,
        TestKey::generate("rotated").map_err(|error| format!("{error:#}"))?,
    ])
});

impl TestKey {
    /// The key the test identity provider publishes.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the keys from being generated.
    pub fn published() -> anyhow::Result<&'static Self> {
        let [published, _, _] = KEYS.as_ref().map_err(|error| anyhow!("{error}"))?;
        Ok(published)
    }

    /// A key the test identity provider does not publish.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the keys from being generated.
    pub fn unpublished() -> anyhow::Result<&'static Self> {
        let [_, unpublished, _] = KEYS.as_ref().map_err(|error| anyhow!("{error}"))?;
        Ok(unpublished)
    }

    /// A key the test identity provider publishes while the server runs, as in a key rotation.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the keys from being generated.
    pub fn rotated() -> anyhow::Result<&'static Self> {
        let [_, _, rotated] = KEYS.as_ref().map_err(|error| anyhow!("{error}"))?;
        Ok(rotated)
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

/// The test identity provider's JWK Set endpoint, on a free port of this machine until the test's
/// runtime shuts down.
pub struct KeyServer {
    /// Where the keys are published.
    url: Url,
    /// The keys published now.
    keys: Arc<RwLock<JwkSet>>,
    /// How many times the keys have been fetched.
    fetches: Arc<AtomicUsize>,
    /// Whether requests go unanswered.
    hanging: Arc<AtomicBool>,
}

impl KeyServer {
    /// Starts publishing `keys`.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the server from listening.
    pub async fn start(keys: &[&TestKey]) -> anyhow::Result<Self> {
        let keys = Arc::new(RwLock::new(JwkSet {
            keys: keys.iter().map(|key| key.jwk.clone()).collect(),
        }));
        let fetches = Arc::new(AtomicUsize::new(0));
        let served = Arc::clone(&keys);
        let counted = Arc::clone(&fetches);
        let hanging = Arc::new(AtomicBool::new(false));
        let hangs = Arc::clone(&hanging);
        let url = listen(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            if hangs.load(Ordering::SeqCst) {
                return Ok(None);
            }
            Ok(Some(Response::new(Full::new(encode(&served)?))))
        })
        .await?;
        Ok(Self {
            url,
            keys,
            fetches,
            hanging,
        })
    }

    /// Where the keys are published.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// How many times the keys have been fetched.
    #[must_use]
    pub fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    /// Adds `key` to the published keys.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the keys from being updated.
    pub fn publish(&self, key: &TestKey) -> anyhow::Result<()> {
        self.keys
            .write()
            .map_err(|error| anyhow!("writing the published keys: {error}"))?
            .keys
            .push(key.jwk.clone());
        Ok(())
    }

    /// Leaves every later request unanswered, standing in for an identity provider that hangs. The
    /// requests still count as fetches.
    pub fn hang(&self) {
        self.hanging.store(true, Ordering::SeqCst);
    }
}

/// Starts a JWK Set endpoint that answers every request with 503 Service Unavailable, standing in
/// for an identity provider that cannot serve its keys, and returns where it listens.
///
/// # Errors
///
/// Returns the error that kept the endpoint from listening.
pub async fn failing_key_endpoint() -> anyhow::Result<Url> {
    listen(|| {
        Ok(Some(
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::default())?,
        ))
    })
    .await
}

/// Starts a JWK Set endpoint that never answers, standing in for an identity provider that hangs,
/// and returns where it listens.
///
/// # Errors
///
/// Returns the error that kept the endpoint from listening.
pub async fn hanging_key_endpoint() -> anyhow::Result<Url> {
    listen(|| Ok(None)).await
}

/// Serves HTTP/1.1 on a free port of this machine until the test's runtime shuts down, answering
/// every request with what `respond` returns, or never when it returns `None`, and returns the JWK
/// Set URL there.
async fn listen<F>(respond: F) -> anyhow::Result<Url>
where
    F: Fn() -> anyhow::Result<Option<Response<Full<Bytes>>>> + Clone + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = Url::parse(&format!("http://{}/jwks", listener.local_addr()?))?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let respond = respond.clone();
            let service = service_fn(move |_request| {
                let response = respond();
                async move {
                    match response? {
                        Some(response) => anyhow::Ok(response),
                        None => future::pending().await,
                    }
                }
            });
            tokio::spawn(http1::Builder::new().serve_connection(TokioIo::new(stream), service));
        }
    });
    Ok(url)
}

/// The JSON of the key set `keys` holds now.
fn encode(keys: &RwLock<JwkSet>) -> anyhow::Result<Bytes> {
    let keys = keys
        .read()
        .map_err(|error| anyhow!("reading the published keys: {error}"))?;
    Ok(Bytes::from(serde_json::to_vec(&*keys)?))
}
