//! The Shuftle multiplayer server.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::Context;
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
};

/// gRPC's conventional port.
const PORT: u16 = 50051;

/// Where the server listens: this machine only.
const LISTEN_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT));

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind(LISTEN_ADDR)
        .await
        .with_context(|| format!("binding {LISTEN_ADDR}"))?;
    let mut terminate = signal(SignalKind::terminate()).context("listening for SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("listening for SIGINT")?;
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    };
    shuftle_server::serve(listener, shutdown)
        .await
        .context("serving")
}
