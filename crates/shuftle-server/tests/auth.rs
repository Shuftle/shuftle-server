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
use test_utils::{
    Claims, KeyServer, TestKey, check_against_server, failing_key_endpoint, hanging_key_endpoint,
    spawn_server, spawn_server_with_keys,
};
use tokio::{
    task::JoinSet,
    time::{Instant, advance, sleep, timeout},
};
use tonic::{Code, Request, Status, client::Grpc, metadata::MetadataValue, transport::Channel};
use tonic_prost::ProstCodec;

/// What the server tells callers whose token it refuses.
const SIGN_IN_AGAIN: &str = "invalid access token, sign in again";

/// What the server tells callers when it cannot check their token.
const RETRY_LATER: &str = "cannot verify access tokens right now, retry later";

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
    ensure_accepted(address, &token).await
}

#[tokio::test]
async fn refuses_tokens_with_a_bad_signature() -> anyhow::Result<()> {
    let token =
        TestKey::unpublished()?.sign_naming(TestKey::published()?, &Claims::valid(PLAYER)?)?;

    let address = spawn_server().await?;
    ensure_refused(address, &token).await
}

#[tokio::test]
async fn accepts_keys_published_after_start() -> anyhow::Result<()> {
    let keys = KeyServer::start(&[TestKey::published()?]).await?;
    let address = spawn_server_with_keys(keys.url()).await?;
    let before = TestKey::published()?.sign(&Claims::valid(PLAYER)?)?;
    ensure_accepted(address, &before)
        .await
        .context("before the rotation")?;

    keys.publish(TestKey::rotated()?)?;
    let after = TestKey::rotated()?.sign(&Claims::valid(PLAYER)?)?;

    ensure_accepted(address, &after).await
}

#[tokio::test]
async fn refuses_with_unavailable_when_keys_cannot_be_fetched() -> anyhow::Result<()> {
    let token = TestKey::published()?.sign(&Claims::valid(PLAYER)?)?;

    let address = spawn_server_with_keys(&failing_key_endpoint().await?).await?;
    ensure_unavailable(address, &token).await
}

/// How long a call may take on the paused clock before the test counts it as hanging: longer than
/// any timeout the server uses.
const HANG_GUARD: Duration = Duration::from_mins(1);

#[tokio::test(start_paused = true)]
async fn refuses_with_unavailable_when_keys_hang() -> anyhow::Result<()> {
    let token = TestKey::published()?.sign(&Claims::valid(PLAYER)?)?;

    let address = spawn_server_with_keys(&hanging_key_endpoint().await?).await?;
    timeout(HANG_GUARD, ensure_unavailable(address, &token))
        .await
        .context("the call hung")?
}

#[tokio::test(start_paused = true)]
async fn refetches_keys_older_than_max_age() -> anyhow::Result<()> {
    let keys = KeyServer::start(&[TestKey::published()?]).await?;
    let address = spawn_server_with_keys(keys.url()).await?;
    let token = TestKey::published()?.sign(&Claims::valid(PLAYER)?)?;
    ensure_accepted(address, &token)
        .await
        .context("first call")?;

    advance(MAX_KEY_AGE + Duration::from_secs(1)).await;
    ensure_accepted(address, &token).await?;

    let fetches = keys.fetches();
    ensure!(fetches == 2, "{fetches} fetches, expected 2");
    Ok(())
}

/// How long the server trusts the keys it fetched.
const MAX_KEY_AGE: Duration = Duration::from_mins(10);

/// How long before the keys expire the server starts refetching them in the background.
const REFRESH_AHEAD: Duration = Duration::from_mins(2);

/// How often the test checks the key server while waiting for a background fetch.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[tokio::test(start_paused = true)]
async fn refreshes_keys_in_the_background_before_they_expire() -> anyhow::Result<()> {
    let keys = KeyServer::start(&[TestKey::published()?]).await?;
    let address = spawn_server_with_keys(keys.url()).await?;
    let token = TestKey::published()?.sign(&Claims::valid(PLAYER)?)?;
    ensure_accepted(address, &token)
        .await
        .context("first call")?;

    keys.hang();
    advance(MAX_KEY_AGE - REFRESH_AHEAD + Duration::from_secs(1)).await;
    // On the paused clock, time only passes while a call waits on a timer, such as a fetch timeout.
    let before = Instant::now();
    ensure_accepted(address, &token).await?;
    let waited = before.elapsed();
    ensure!(
        waited.is_zero(),
        "the call waited {waited:?} for the refresh"
    );

    timeout(HANG_GUARD, async {
        while keys.fetches() < 2 {
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .context("no background refresh")
}

#[tokio::test]
async fn serves_known_keys_from_cache() -> anyhow::Result<()> {
    let keys = KeyServer::start(&[TestKey::published()?]).await?;
    let address = spawn_server_with_keys(keys.url()).await?;
    let token = TestKey::published()?.sign(&Claims::valid(PLAYER)?)?;
    ensure_accepted(address, &token)
        .await
        .context("first call")?;

    ensure_accepted(address, &token).await?;
    let fetches = keys.fetches();
    ensure!(fetches == 1, "{fetches} fetches, expected 1");
    Ok(())
}

/// How many players call at once in the concurrency test.
const SIMULTANEOUS_CALLS: usize = 10;

#[tokio::test]
async fn simultaneous_calls_share_one_fetch() -> anyhow::Result<()> {
    let keys = KeyServer::start(&[TestKey::published()?]).await?;
    let address = spawn_server_with_keys(keys.url()).await?;
    let token = TestKey::published()?.sign(&Claims::valid(PLAYER)?)?;

    let mut calls = JoinSet::new();
    for _ in 0..SIMULTANEOUS_CALLS {
        let token = token.clone();
        calls.spawn(async move { ensure_accepted(address, &token).await });
    }
    while let Some(call) = calls.join_next().await {
        call??;
    }

    let fetches = keys.fetches();
    ensure!(fetches == 1, "{fetches} fetches, expected 1");
    Ok(())
}

#[tokio::test]
async fn limits_key_refetches() -> anyhow::Result<()> {
    let keys = KeyServer::start(&[TestKey::published()?]).await?;
    let address = spawn_server_with_keys(keys.url()).await?;
    let token = TestKey::unpublished()?.sign(&Claims::valid(PLAYER)?)?;
    ensure_refused(address, &token)
        .await
        .context("first unknown key")?;

    ensure_unavailable(address, &token).await?;
    let fetches = keys.fetches();
    ensure!(fetches == 1, "{fetches} fetches, expected 1");
    Ok(())
}

/// Fails unless the server at `address` answers a call carrying `token` with UNAVAILABLE, telling
/// the caller to retry later.
async fn ensure_unavailable(address: SocketAddr, token: &str) -> anyhow::Result<()> {
    let result = enqueue_with_authorization(address, &format!("Bearer {token}")).await?;

    ensure!(
        result.as_ref().is_err_and(
            |status| status.code() == Code::Unavailable && status.message() == RETRY_LATER
        ),
        "got {result:?}, expected UNAVAILABLE with {RETRY_LATER:?}"
    );
    Ok(())
}

/// Fails unless the server at `address` lets a call carrying `token` reach its service. The empty
/// matchmaking service answers UNIMPLEMENTED once a call gets past authentication.
async fn ensure_accepted(address: SocketAddr, token: &str) -> anyhow::Result<()> {
    let result = enqueue_with_authorization(address, &format!("Bearer {token}")).await?;

    ensure!(
        result
            .as_ref()
            .is_err_and(|status| status.code() == Code::Unimplemented),
        "got {result:?}, expected the call to reach the service and get UNIMPLEMENTED"
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

/// Fails unless the server at `address` refuses a call carrying `token`, telling the caller to sign
/// in again.
async fn ensure_refused(address: SocketAddr, token: &str) -> anyhow::Result<()> {
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
        let token = TestKey::published().and_then(|key| {
            key.sign(&Claims {
                iss,
                ..valid.clone()
            })
        });
        async move { ensure_refused(address, &token?).await }
    })
}

#[test]
fn refuses_tokens_for_other_audiences() -> anyhow::Result<()> {
    let valid = Claims::valid(PLAYER)?;
    check_against_server(file!(), &other_than(valid.aud.clone()), |address, aud| {
        let token = TestKey::published().and_then(|key| {
            key.sign(&Claims {
                aud,
                ..valid.clone()
            })
        });
        async move { ensure_refused(address, &token?).await }
    })
}

#[test]
fn refuses_expired_tokens() -> anyhow::Result<()> {
    let valid = Claims::valid(PLAYER)?;
    let an_hour_ago = SystemTime::now().duration_since(UNIX_EPOCH)? - Duration::from_hours(1);
    check_against_server(file!(), &(0..=an_hour_ago.as_secs()), |address, exp| {
        let token = TestKey::published().and_then(|key| {
            key.sign(&Claims {
                exp,
                ..valid.clone()
            })
        });
        async move { ensure_refused(address, &token?).await }
    })
}
