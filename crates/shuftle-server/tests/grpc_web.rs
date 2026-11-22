//! gRPC-Web, the protocol browsers use. It applies to every service alike.

use anyhow::ensure;
use bytes::Bytes;
use http::{HeaderValue, Request, header::CONTENT_TYPE};
use http_body_util::Full;
use test_utils::{EMPTY_MESSAGE, GRPC_WEB, http2_client, spawn_server};

#[tokio::test]
async fn grpc_web_requests_get_grpc_web_responses() -> anyhow::Result<()> {
    let address = spawn_server().await?;
    let client = http2_client();
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
