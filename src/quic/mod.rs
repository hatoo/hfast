//! A QUIC server, only as much of one as answering a benchmark needs
//!
//! The TLS handshake, the key schedule and the AEAD come from rustls, the same
//! way [`crate::h3`]'s did from quinn. What is here is the transport around
//! them: packets, frames, streams, acknowledgement and the little recovery a
//! path that mostly works needs.
//!
//! See README.md for what it leaves out and why a load generator does not
//! notice.

pub mod assemble;
pub mod conn;
pub mod endpoint;
pub mod frame;
pub mod packet;
pub mod transport;
mod udp;
pub mod wire;

/// The AEAD tag every packet carries (RFC 9001 Section 5.3)
pub const TAG_LEN: usize = 16;

/// What this server sends without probing for a larger path. RFC 9000 Section
/// 14.1 makes 1200 the least any path must carry.
pub const MAX_DATAGRAM: usize = 1200;
