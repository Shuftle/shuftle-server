//! Authentication: calls outside the public services need a valid access token.

use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, ensure};
use http::uri::PathAndQuery;
use proptest::{
    prop_oneof,
    strategy::{Just, Strategy},
};
use prost::Message;
use prost_types::FileDescriptorSet;
use shuftle_proto::FILE_DESCRIPTOR_SET;
use shuftle_proto::shuftle::matchmaking::v1::{
    EnqueueRequest, matchmaking_service_client::MatchmakingServiceClient,
};
use test_utils::{Claims, TestKey, check_against_server, spawn_server};
use tonic::{Code, Request, Status, client::Grpc, metadata::MetadataValue, transport::Channel};
use tonic_prost::ProstCodec;

/// What the server tells callers whose token it refuses.
const SIGN_IN_AGAIN: &str = "invalid access token, sign in again";

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
            status.code() == Code::Unauthenticated && status.message() == SIGN_IN_AGAIN
        });
        if public {
            ensure!(!refused, "{path} is public, got {result:?}");
        } else {
            ensure!(
                refused,
                "{path}: got {result:?}, expected UNAUTHENTICATED with {SIGN_IN_AGAIN:?}"
            );
        }
    }
    Ok(())
}

/// A player id as the identity provider issues it.
const PLAYER: &str = "6f1c7c4e-0b7a-4b5e-9d2a-3f8e2c1d5a90";

#[tokio::test]
async fn lets_valid_tokens_through() -> anyhow::Result<()> {
    let token = TestKey::published()?.sign(&Claims::valid(PLAYER)?)?;

    let address = spawn_server().await?;
    let result = enqueue_with_authorization(address, &format!("Bearer {token}")).await?;

    // The empty matchmaking service answers UNIMPLEMENTED once a call gets past authentication.
    ensure!(
        result
            .as_ref()
            .is_err_and(|status| status.code() == Code::Unimplemented),
        "got {result:?}, expected the call to reach the service and get UNIMPLEMENTED"
    );
    Ok(())
}

#[tokio::test]
async fn refuses_tokens_with_a_bad_signature() -> anyhow::Result<()> {
    let token =
        TestKey::unpublished()?.sign_naming(TestKey::published()?, &Claims::valid(PLAYER)?)?;

    let address = spawn_server().await?;
    let result = enqueue_with_authorization(address, &format!("Bearer {token}")).await?;

    let refused = result.as_ref().is_err_and(|status| {
        status.code() == Code::Unauthenticated && status.message() == SIGN_IN_AGAIN
    });
    ensure!(
        refused,
        "got {result:?}, expected UNAUTHENTICATED with {SIGN_IN_AGAIN:?}"
    );
    Ok(())
}

/// Calls `Enqueue` on the server at `address`, standing in for any call that needs a token, with
/// `authorization` set to `value`.
async fn enqueue_with_authorization(
    address: SocketAddr,
    value: &str,
) -> anyhow::Result<Result<(), Status>> {
    let mut client = MatchmakingServiceClient::connect(format!("http://{address}")).await?;
    let mut request = Request::new(EnqueueRequest::default());
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::try_from(value)?);
    Ok(client.enqueue(request).await.map(|_| ()))
}

/// Strings other than `expected`: arbitrary text, and near misses that extend it or change its
/// case.
fn other_than(expected: String) -> impl Strategy<Value = String> {
    let extended = expected.clone();
    let recased = expected.to_uppercase();
    prop_oneof![
        "\\PC{0,40}",
        "[ -~]{1,5}".prop_map(move |suffix| format!("{extended}{suffix}")),
        Just(recased),
    ]
    .prop_filter("the expected value", move |other| *other != expected)
}

/// Fails unless the server at `address` refuses a token carrying `claims`, signed with the
/// published key.
async fn ensure_refused(address: SocketAddr, claims: Claims) -> anyhow::Result<()> {
    let token = TestKey::published()?.sign(&claims)?;
    let result = enqueue_with_authorization(address, &format!("Bearer {token}")).await?;

    ensure!(
        result
            .as_ref()
            .is_err_and(|status| status.code() == Code::Unauthenticated
                && status.message() == SIGN_IN_AGAIN),
        "got {result:?}, expected UNAUTHENTICATED with {SIGN_IN_AGAIN:?}"
    );
    Ok(())
}

#[test]
fn refuses_tokens_from_other_issuers() -> anyhow::Result<()> {
    let valid = Claims::valid(PLAYER)?;
    check_against_server(file!(), &other_than(valid.iss.clone()), |address, iss| {
        ensure_refused(
            address,
            Claims {
                iss,
                ..valid.clone()
            },
        )
    })
}

#[test]
fn refuses_tokens_for_other_audiences() -> anyhow::Result<()> {
    let valid = Claims::valid(PLAYER)?;
    check_against_server(file!(), &other_than(valid.aud.clone()), |address, aud| {
        ensure_refused(
            address,
            Claims {
                aud,
                ..valid.clone()
            },
        )
    })
}

#[test]
fn refuses_expired_tokens() -> anyhow::Result<()> {
    let valid = Claims::valid(PLAYER)?;
    let an_hour_ago = SystemTime::now().duration_since(UNIX_EPOCH)? - Duration::from_hours(1);
    check_against_server(file!(), &(0..=an_hour_ago.as_secs()), |address, exp| {
        ensure_refused(
            address,
            Claims {
                exp,
                ..valid.clone()
            },
        )
    })
}
