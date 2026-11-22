//! Helpers shared by the Shuftle server's tests.

use std::{future, net::SocketAddr};

use http_body::Body;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use proptest::test_runner::TestCaseError;
use shuftle_server::config::Cors;
use tokio::{net::TcpListener, runtime::Builder};

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
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(shuftle_server::serve(listener, cors, future::pending()));
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
