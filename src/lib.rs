//! # snmpify
//!
//! Fast SNMP for Rust: the wire format (a zero-copy BER decoder, a
//! back-to-front encoder that never copies nested values, OIDs stored
//! inline, all SMIv2 value types, every PDU, SNMPv1/v2c and v3 messages),
//! SNMPv3 security ([`usm`]: every standard authentication and privacy
//! protocol), an async client ([`client`]) with walks and mass polling
//! over one socket, and notifications ([`notification`]: traps and
//! informs, sent and received), the agent side ([`agent`], [`agentx`])
//! and MIBs ([`mib`]). The Python and C/C++ bindings are on the
//! [roadmap](https://github.com/snmp-rs/snmpify/blob/main/ROADMAP.md).
//!
//! Features: `client` (default: tokio, implies `v3`), `v3` (USM crypto).
//! Without both, only the wire format, with no dependencies.
//!
//! ```
//! use snmpify::{CommunityMessage, Pdu, Value, VarBind, Version, AnyPdu};
//!
//! // Encode a GetRequest for sysDescr.0 …
//! let request = CommunityMessage::new(Version::V2c, "public", Pdu::get(1, ["1.3.6.1.2.1.1.1.0".parse::<snmpify::Oid>()?]));
//! let bytes: Vec<u8> = request.encode();
//!
//! // … and decode whatever comes back.
//! let reply = CommunityMessage::decode(&bytes)?;
//! if let AnyPdu::Pdu(pdu) = &reply.pdu {
//!     for vb in &pdu.varbinds {
//!         println!("{vb}");
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "client")]
pub mod agent;
#[cfg(feature = "client")]
pub mod agentx;
pub mod ber;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "v3")]
pub mod engine;
mod error;
pub mod mib;
#[cfg(feature = "client")]
pub mod notification;
mod oid;
mod pdu;
#[cfg(feature = "v3")]
pub mod usm;
pub mod v3;
mod value;

pub use error::{DecodeError, DecodeErrorKind, ParseOidError};
pub use oid::Oid;
pub use pdu::{
    peek_version, AnyPdu, CommunityMessage, ErrorStatus, Pdu, PduType, TrapV1Pdu, Version,
};
pub use value::{Value, VarBind};

// Compile the README examples as doctests.
#[cfg(all(doctest, feature = "client"))]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
