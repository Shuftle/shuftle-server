//! Authentication: calls outside the public services need a valid access token.

use anyhow::{Context, ensure};
use http::uri::PathAndQuery;
use proptest::{prop_assert, proptest, strategy::Strategy};
use prost::Message;
use prost_types::FileDescriptorSet;
use shuftle_proto::FILE_DESCRIPTOR_SET;
use shuftle_proto::shuftle::matchmaking::v1::{
    EnqueueRequest, matchmaking_service_client::MatchmakingServiceClient,
};
use test_utils::{Claims, TestKey, block_on, spawn_server};
use tonic::{Code, Request, Status, client::Grpc, metadata::MetadataValue, transport::Channel};
use tonic_prost::ProstCodec;

/// The services anyone may call without a token.
const PUBLIC_SERVICES: [&str; 1] = ["shuftle.version.v1.VersionService"];

/// The gRPC path of every method in the protocol, with whether its service is public.
fn methods() -> anyhow::Result<Vec<(String, bool)>> {
    let descriptors = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET)?;
    let mut methods = Vec::new();
    for file in descriptors.file {
        let package = file.package();
        for service in &file.service {
            let service_name = format!("{package}.{}", service.name());
            let public = PUBLIC_SERVICES.contains(&service_name.as_str());
            for method in &service.method {
                methods.push((format!("/{service_name}/{}", method.name()), public));
            }
        }
    }
    Ok(methods)
}

/// Calls `path` without a token, with an empty message, which every proto3 request type accepts.
async fn call_without_token(channel: Channel, path: &str) -> anyhow::Result<Result<(), Status>> {
    let mut grpc = Grpc::new(channel);
    grpc.ready().await?;
    let path = PathAndQuery::try_from(path).with_context(|| format!("path {path}"))?;
    Ok(grpc
        .unary(Request::new(()), path, ProstCodec::<(), ()>::default())
        .await
        .map(|_| ()))
}

#[tokio::test]
async fn refuses_calls_without_a_token() -> anyhow::Result<()> {
    let address = spawn_server().await?;
    let channel = Channel::from_shared(format!("http://{address}"))?
        .connect()
        .await?;

    for (path, public) in methods()? {
        let result = call_without_token(channel.clone(), &path).await?;
        let refused = result.as_ref().is_err_and(|status| {
            status.code() == Code::Unauthenticated
                && status.message() == "missing authorization metadata"
        });
        if public {
            ensure!(!refused, "{path} is public, got {result:?}");
        } else {
            ensure!(
                refused,
                "{path}: got {result:?}, expected UNAUTHENTICATED with \"missing authorization \
                 metadata\""
            );
        }
    }
    Ok(())
}

/// `authorization` values whose scheme is not `Bearer`, which RFC 7235 matches case-insensitively.
fn non_bearer_authorization() -> impl Strategy<Value = String> {
    "[!-~][ -~]{0,40}".prop_filter("Bearer scheme", |value| {
        !value.to_ascii_lowercase().starts_with("bearer ")
    })
}

/// A player id as the identity provider issues it.
const PLAYER: &str = "6f1c7c4e-0b7a-4b5e-9d2a-3f8e2c1d5a90";

#[tokio::test]
async fn refuses_tokens_signed_with_unpublished_keys() -> anyhow::Result<()> {
    let token = TestKey::unpublished()?.sign(&Claims::valid(PLAYER)?)?;

    let result = enqueue_with_authorization(&format!("Bearer {token}")).await?;

    let refused = result.as_ref().is_err_and(|status| {
        status.code() == Code::Unauthenticated && status.message() == "unknown signing key"
    });
    ensure!(
        refused,
        "got {result:?}, expected UNAUTHENTICATED with \"unknown signing key\""
    );
    Ok(())
}

/// Bearer tokens (RFC 6750 `b64token` characters) that are not JWTs: dot-separated base64url
/// segments whose header does not decode to a JOSE header.
fn not_a_jwt() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{1,20}(\\.[A-Za-z0-9_-]{0,20}){0,4}"
}

/// Calls `Enqueue`, standing in for any call that needs a token, with `authorization` set to
/// `value`.
async fn enqueue_with_authorization(value: &str) -> anyhow::Result<Result<(), Status>> {
    let address = spawn_server().await?;
    let mut client = MatchmakingServiceClient::connect(format!("http://{address}")).await?;
    let mut request = Request::new(EnqueueRequest::default());
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::try_from(value)?);
    Ok(client.enqueue(request).await.map(|_| ()))
}

proptest! {
    #[test]
    fn refuses_schemes_other_than_bearer(value in non_bearer_authorization()) {
        let result = block_on(enqueue_with_authorization(&value))?;

        prop_assert!(
            result.as_ref().is_err_and(|status| status.code() == Code::Unauthenticated
                && status.message() == "authorization is not a Bearer token"),
            "got {result:?}, expected UNAUTHENTICATED with \"authorization is not a Bearer token\""
        );
    }

    #[test]
    fn refuses_bearer_tokens_that_are_not_jwts(token in not_a_jwt()) {
        let result = block_on(enqueue_with_authorization(&format!("Bearer {token}")))?;

        prop_assert!(
            result.as_ref().is_err_and(|status| status.code() == Code::Unauthenticated
                && status.message() == "malformed token"),
            "got {result:?}, expected UNAUTHENTICATED with \"malformed token\""
        );
    }
}
