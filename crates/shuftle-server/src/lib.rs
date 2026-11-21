//! The Shuftle multiplayer server.

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
/// Returns the transport error that stopped the server.
pub async fn serve(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), tonic::transport::Error> {
    Server::builder()
        .accept_http1(true)
        .layer(GrpcWebLayer::new())
        .add_service(VersionServiceServer::new(Version))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
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
