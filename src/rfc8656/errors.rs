//! Error codes that are defined in RFC 8656.
use crate::rfc5389::attributes::ErrorCode;

/// The server does not support the address family requested by the client.
///
/// See <https://datatracker.ietf.org/doc/html/rfc8656#section-19-2.6> for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressFamilyNotSupported;

impl AddressFamilyNotSupported {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 440;
}
impl From<AddressFamilyNotSupported> for ErrorCode {
    fn from(_: AddressFamilyNotSupported) -> Self {
        ErrorCode::new(
            AddressFamilyNotSupported::CODEPOINT,
            "Address Family not Supported".to_string(),
        )
        .expect("never fails")
    }
}

/// A peer address is part of a different address family than that of the relayed transport address of the allocation.
///
/// See <https://datatracker.ietf.org/doc/html/rfc8656#section-19-2.12> for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerAddressFamilyMismatch;
impl PeerAddressFamilyMismatch {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 443;
}
impl From<PeerAddressFamilyMismatch> for ErrorCode {
    fn from(_: PeerAddressFamilyMismatch) -> Self {
        ErrorCode::new(
            PeerAddressFamilyMismatch::CODEPOINT,
            "Peer Address Family Mismatch".to_owned(),
        )
        .expect("never fails")
    }
}
