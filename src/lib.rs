//! # snmpify
//!
//! Fast SNMP for Rust: the wire format (a zero-copy BER decoder, a
//! back-to-front encoder that never copies nested values, OIDs stored
//! inline, all SMIv2 value types, every PDU, SNMPv1/v2c messages) and an
//! async client ([`client`]) with walks and mass polling over one socket.
//! SNMPv3, notifications and the Python and C/C++ bindings are on the
//! [roadmap](https://github.com/snmp-rs/snmpify/blob/main/ROADMAP.md).
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

pub mod ber;
#[cfg(feature = "client")]
pub mod client;
mod error;
mod oid;
mod pdu;
mod value;

pub use error::{DecodeError, DecodeErrorKind, ParseOidError};
pub use oid::Oid;
pub use pdu::{
    peek_version, AnyPdu, CommunityMessage, ErrorStatus, Pdu, PduType, TrapV1Pdu, Version,
};
pub use value::{Value, VarBind};

// Compile the README examples as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
