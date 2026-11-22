//! The Shuftle protocol: the gRPC code generated from the `shuftle-protocol` submodule.

/// The protocol version the generated code speaks, from the submodule's `version.txt`.
pub const PROTOCOL_VERSION: semver::Version =
    include!(concat!(env!("OUT_DIR"), "/protocol_version.rs"));

pub use generated::shuftle;

#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/protos.rs"));
}

/// The encoded descriptors of every protobuf file, for gRPC server reflection.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/descriptors.bin"));
