//! The Shuftle multiplayer server.

use anyhow::Context;
use shuftle_proto::{
    PROTOCOL_VERSION,
    shuftle::version::v1::{
        self, GetVersionRequest, GetVersionResponse,
        version_service_server::{VersionService, VersionServiceServer},
    },
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, transport::Server};
use tonic_web::GrpcWebLayer;

/// Serves every service on `listener`, over gRPC and gRPC-Web, until `shutdown` completes.
///
/// # Errors
///
/// Returns the error that kept the server from starting or stopped it.
pub async fn serve(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let router = Server::builder()
        .accept_http1(cfg!(feature = "dev"))
        .layer(GrpcWebLayer::new())
        .add_service(VersionServiceServer::new(Version));
    #[cfg(feature = "dev")]
    let router = router.add_service(
        tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(shuftle_proto::FILE_DESCRIPTOR_SET)
            .build_v1()
            .context("building the reflection service")?,
    );
    router
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
        .context("serving")
}

/// Answers which protocol version the server speaks.
struct Version;

#[tonic::async_trait]
impl VersionService for Version {
    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        let part = |part: u64| {
            u32::try_from(part).map_err(|_| {
                Status::internal(format!(
                    "protocol version {PROTOCOL_VERSION} does not fit the version message"
                ))
            })
        };
        let version = v1::Version {
            major: part(PROTOCOL_VERSION.major)?,
            minor: part(PROTOCOL_VERSION.minor)?,
            patch: part(PROTOCOL_VERSION.patch)?,
        };
        Ok(Response::new(GetVersionResponse {
            version: Some(version),
        }))
    }
}
