//! gRPC-Web, the protocol browsers use. It applies to every service alike.

use anyhow::ensure;
use bytes::Bytes;
use http::{HeaderValue, Request, header::CONTENT_TYPE};
use http_body_util::Full;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use test_utils::spawn_server;

/// The content type of gRPC-Web requests and responses carrying protobuf.
const GRPC_WEB: &str = "application/grpc-web+proto";

/// A gRPC message frame holding an empty message: no compression flag, then a length of 0.
const EMPTY_MESSAGE: [u8; 5] = [0; 5];

#[tokio::test]
async fn grpc_web_requests_get_grpc_web_responses() -> anyhow::Result<()> {
    let address = spawn_server().await?;
    let client = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();
    let request = Request::post(format!(
        "http://{address}/shuftle.version.v1.VersionService/GetVersion"
    ))
    .header(CONTENT_TYPE, GRPC_WEB)
    .body(Full::new(Bytes::from_static(&EMPTY_MESSAGE)))?;

    let response = client.request(request).await?;

    let content_type = response.headers().get(CONTENT_TYPE);
    ensure!(
        content_type == Some(&HeaderValue::from_static(GRPC_WEB)),
        "got content type {content_type:?}, expected {GRPC_WEB}"
    );
    Ok(())
}
