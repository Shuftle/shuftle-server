//! The version service.

use anyhow::ensure;
use shuftle_proto::shuftle::version::v1::{
    GetVersionRequest, Version, version_service_client::VersionServiceClient,
};
use test_utils::spawn_server;

#[tokio::test]
async fn get_version_returns_the_version_of_the_protocol_submodule() -> anyhow::Result<()> {
    let file = include_str!("../../../shuftle-protocol/version.txt");
    let expected = semver::Version::parse(file.trim())?;
    let address = spawn_server().await?;

    let mut client = VersionServiceClient::connect(format!("http://{address}")).await?;
    let response = client.get_version(GetVersionRequest {}).await?;

    let expected = Version {
        major: expected.major.try_into()?,
        minor: expected.minor.try_into()?,
        patch: expected.patch.try_into()?,
    };
    let actual = response.into_inner().version;
    ensure!(
        actual == Some(expected),
        "got {actual:?}, expected {expected:?}"
    );
    Ok(())
}
