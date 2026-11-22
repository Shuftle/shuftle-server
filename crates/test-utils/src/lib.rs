//! Helpers shared by the Shuftle server's tests.

use std::{future, net::SocketAddr};

use tokio::net::TcpListener;

/// Starts the server on a free port of this machine and returns its address. The server runs
/// until the test's runtime shuts down.
///
/// # Errors
///
/// Returns the error that kept the server from listening.
pub async fn spawn_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(shuftle_server::serve(listener, future::pending()));
    Ok(address)
}
