//! The Shuftle multiplayer server.

pub mod config;

use std::time::Duration;

use anyhow::Context;
use config::Cors;
use http::{HeaderName, HeaderValue, Method, header::CONTENT_TYPE};
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
use tower_http::cors::{AllowOrigin, CorsLayer};

/// How long browsers may reuse a preflight's answer: a day, as tonic-web's former built-in CORS
/// support used. Browsers may cap it lower.
const PREFLIGHT_MAX_AGE: Duration = Duration::from_hours(24);

/// The request headers browser pages may send: gRPC-Web's, and the protocol version every call
/// but `GetVersion` carries.
const ALLOWED_HEADERS: [HeaderName; 5] = [
    CONTENT_TYPE,
    HeaderName::from_static("x-grpc-web"),
    HeaderName::from_static("x-user-agent"),
    HeaderName::from_static("grpc-timeout"),
    HeaderName::from_static("shuftle-protocol-version"),
];

/// The response headers browser pages may read: the call's gRPC status.
const EXPOSED_HEADERS: [HeaderName; 3] = [
    HeaderName::from_static("grpc-status"),
    HeaderName::from_static("grpc-message"),
    HeaderName::from_static("grpc-status-details-bin"),
];

/// Serves every service on `listener`, over gRPC and gRPC-Web to the browser pages `cors` allows,
/// until `shutdown` completes.
///
/// # Errors
///
/// Returns the error that kept the server from starting or stopped it.
pub async fn serve(
    listener: TcpListener,
    cors: Cors,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let router = Server::builder()
        .accept_http1(cfg!(feature = "dev"))
        .layer(cors_layer(&cors)?)
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

/// Lets the pages `cors` allows make gRPC-Web calls, without credentials.
fn cors_layer(cors: &Cors) -> anyhow::Result<CorsLayer> {
    let origins = cors
        .allowed_origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin.as_str())
                .with_context(|| format!("`{}` is not a header value", origin.as_str()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::POST])
        .allow_headers(ALLOWED_HEADERS)
        .expose_headers(EXPOSED_HEADERS)
        .max_age(PREFLIGHT_MAX_AGE))
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
