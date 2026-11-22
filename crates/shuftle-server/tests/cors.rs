//! Cross-origin access for browser pages.

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, Method, Request,
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
        ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_REQUEST_HEADERS,
        ACCESS_CONTROL_REQUEST_METHOD, CONTENT_TYPE, ORIGIN,
    },
};
use http_body_util::{Empty, Full};
use proptest::{collection, prop_assert, proptest, strategy::Strategy, test_runner::TestCaseError};
use shuftle_server::config::{AllowedOrigin, Cors, test_utils::canonical_origin};
use test_utils::{EMPTY_MESSAGE, GRPC_WEB, block_on, http2_client, spawn_server_with_cors};

/// The response headers browser pages must be able to read: the call's gRPC status.
const STATUS_HEADERS: [&str; 3] = ["grpc-status", "grpc-message", "grpc-status-details-bin"];

/// The most allowed origins a generated configuration has.
const MAX_ALLOWED: usize = 4;

/// The headers gRPC-Web clients send, plus the protocol version every call but `GetVersion`
/// carries.
const REQUEST_HEADERS: [&str; 5] = [
    "content-type",
    "x-grpc-web",
    "x-user-agent",
    "grpc-timeout",
    "shuftle-protocol-version",
];

/// Sends the preflight a browser sends before a gRPC-Web call from `origin`, to a server allowing
/// `allowed`, and returns the response's headers.
async fn preflight(allowed: Vec<AllowedOrigin>, origin: &str) -> anyhow::Result<HeaderMap> {
    let address = spawn_server_with_cors(Cors {
        allowed_origins: allowed,
    })
    .await?;
    let client = http2_client();
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri(format!(
            "http://{address}/shuftle.version.v1.VersionService/GetVersion"
        ))
        .header(ORIGIN, origin)
        .header(ACCESS_CONTROL_REQUEST_METHOD, Method::POST.as_str())
        .header(ACCESS_CONTROL_REQUEST_HEADERS, REQUEST_HEADERS.join(","))
        .body(Empty::<Bytes>::new())?;
    Ok(client.request(request).await?.into_parts().0.headers)
}

/// Makes a gRPC-Web call from `origin` to a server allowing `allowed`, and returns the response's
/// headers.
async fn call(allowed: Vec<AllowedOrigin>, origin: &str) -> anyhow::Result<HeaderMap> {
    let address = spawn_server_with_cors(Cors {
        allowed_origins: allowed,
    })
    .await?;
    let request = Request::post(format!(
        "http://{address}/shuftle.version.v1.VersionService/GetVersion"
    ))
    .header(ORIGIN, origin)
    .header(CONTENT_TYPE, GRPC_WEB)
    .body(Full::new(Bytes::from_static(&EMPTY_MESSAGE)))?;
    Ok(http2_client()
        .request(request)
        .await?
        .into_parts()
        .0
        .headers)
}

/// The lowercase items of the comma-separated header `name`, over all its lines.
fn items(headers: &HeaderMap, name: HeaderName) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|item| item.trim().to_lowercase())
        .collect()
}

/// Up to `MAX_ALLOWED` allowed origins, and an origin that is none of them.
fn allowed_and_other_origin() -> impl Strategy<Value = (Vec<String>, String)> {
    (
        collection::vec(canonical_origin(), 0..=MAX_ALLOWED),
        canonical_origin(),
    )
        .prop_filter("other origin allowed", |(allowed, other)| {
            !allowed.contains(other)
        })
}

/// Converts generated origins to the configuration's type.
fn allowed_origins(origins: &[String]) -> Result<Vec<AllowedOrigin>, TestCaseError> {
    origins
        .iter()
        .map(|origin| {
            AllowedOrigin::try_from(origin.clone())
                .map_err(|error| TestCaseError::fail(error.to_string()))
        })
        .collect()
}

proptest! {
    #[test]
    fn allows_preflights_from_allowed_origins(origin in canonical_origin()) {
        let allowed = AllowedOrigin::try_from(origin.clone())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let headers = block_on(preflight(vec![allowed], &origin))?;

        let allow_origin = headers.get(ACCESS_CONTROL_ALLOW_ORIGIN);
        prop_assert!(
            allow_origin.and_then(|value| value.to_str().ok()) == Some(origin.as_str()),
            "got allowed origin {allow_origin:?}, expected {origin}"
        );
        let methods = items(&headers, ACCESS_CONTROL_ALLOW_METHODS);
        prop_assert!(
            methods.iter().any(|method| method == "post"),
            "got allowed methods {methods:?}, expected POST among them"
        );
        let allowed_headers = items(&headers, ACCESS_CONTROL_ALLOW_HEADERS);
        prop_assert!(
            REQUEST_HEADERS.iter().all(|header| allowed_headers.iter().any(|allowed| allowed == header)),
            "got allowed headers {allowed_headers:?}, expected all of {REQUEST_HEADERS:?}"
        );
    }

    #[test]
    fn refuses_preflights_from_other_origins((allowed, other) in allowed_and_other_origin()) {
        let headers = block_on(preflight(allowed_origins(&allowed)?, &other))?;

        let allow_origin = headers.get(ACCESS_CONTROL_ALLOW_ORIGIN);
        prop_assert!(allow_origin.is_none(), "got allowed origin {allow_origin:?}, expected none");
    }

    #[test]
    fn exposes_the_grpc_status_to_allowed_origins(origin in canonical_origin()) {
        let headers = block_on(call(allowed_origins(std::slice::from_ref(&origin))?, &origin))?;

        let exposed = items(&headers, ACCESS_CONTROL_EXPOSE_HEADERS);
        prop_assert!(
            STATUS_HEADERS.iter().all(|header| exposed.iter().any(|item| item == header)),
            "got exposed headers {exposed:?}, expected all of {STATUS_HEADERS:?}"
        );
    }
}
