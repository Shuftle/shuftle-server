//! Generates the gRPC code and the protocol version from the protocol submodule.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use semver::Version;

fn main() -> anyhow::Result<()> {
    let protocol = Path::new(&env::var("CARGO_MANIFEST_DIR")?).join("../../shuftle-protocol");
    let proto_root = protocol.join("proto");
    let version_file = protocol.join("version.txt");
    println!("cargo::rerun-if-changed={}", proto_root.display());
    println!("cargo::rerun-if-changed={}", version_file.display());

    let mut protos = Vec::new();
    collect_protos(&proto_root, &mut protos)?;
    let descriptors = protox::compile(&protos, [&proto_root])?;
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    tonic_prost_build::configure()
        .client_mod_attribute(".", "#[cfg(feature = \"client\")]")
        // Keeps the stream message small: a snapshot is far larger than the other variants.
        .boxed(".shuftle.table.v1.SubscribeResponse.kind.snapshot")
        .include_file("protos.rs")
        .compile_fds(descriptors)?;

    let text = fs::read_to_string(&version_file)
        .with_context(|| format!("reading {}", version_file.display()))?;
    let version = Version::parse(text.trim())
        .with_context(|| format!("parsing {}", version_file.display()))?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        bail!("{version}: the protocol version has no pre-release or build part");
    }
    for part in [version.major, version.minor, version.patch] {
        if u32::try_from(part).is_err() {
            bail!("{version}: every part must fit the u32 fields of the version message");
        }
    }
    let out = out_dir.join("protocol_version.rs");
    fs::write(
        out,
        format!(
            "semver::Version::new({}, {}, {})",
            version.major, version.minor, version.patch
        ),
    )?;
    Ok(())
}

/// Appends every `.proto` file under `dir` to `protos`.
fn collect_protos(dir: &Path, protos: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_protos(&path, protos)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "proto")
        {
            protos.push(path);
        }
    }
    Ok(())
}
