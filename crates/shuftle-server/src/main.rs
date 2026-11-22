//! The Shuftle multiplayer server.

use std::{fs, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use shuftle_server::config::Config;
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
};

/// The Shuftle multiplayer server.
#[derive(Parser)]
struct Args {
    /// The TOML configuration file.
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let path = args.config.display();
    let config: Config = fs::read_to_string(&args.config)
        .with_context(|| format!("reading {path}"))?
        .parse()
        .with_context(|| format!("reading {path}"))?;
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    let mut terminate = signal(SignalKind::terminate()).context("listening for SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("listening for SIGINT")?;
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    };
    shuftle_server::serve(listener, config.cors, shutdown).await
}
