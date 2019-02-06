//! Error codes that are defined in [RFC 5766 -- 15. New STUN Error Response Codes].
//!
//! [RFC 5766 -- 15. New STUN Error Response Codes]: https://tools.ietf.org/html/rfc5766#section-15
use rfc5389::attributes::ErrorCode;

/// `403`: "Forbidden".
///
/// > The request was valid but cannot be performed due to administrative or similar restrictions.
/// >
/// > [RFC 5766 -- 15. New STUN Error Response Codes]
///
/// [RFC 5766 -- 15. New STUN Error Response Codes]: https://tools.ietf.org/html/rfc5766#section-15
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Forbidden;
impl Forbidden {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 403;
}
impl From<Forbidden> for ErrorCode {
    fn from(_: Forbidden) -> Self {
        ErrorCode::new(Forbidden::CODEPOINT, "Forbidden".to_owned()).expect("never fails")
    }
}

/// `437`: "Allocation Mismatch".
///
/// > A request was received by the server that requires an allocation to be in place, but no allocation exists,
/// > or a request was received that requires no allocation, but an allocation exists.
/// >
/// > [RFC 5766 -- 15. New STUN Error Response Codes]
///
/// [RFC 5766 -- 15. New STUN Error Response Codes]: https://tools.ietf.org/html/rfc5766#section-15
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationMismatch;
impl AllocationMismatch {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 437;
}
impl From<AllocationMismatch> for ErrorCode {
    fn from(_: AllocationMismatch) -> Self {
        ErrorCode::new(
            AllocationMismatch::CODEPOINT,
            "Allocation Mismatch".to_owned(),
        )
        .expect("never fails")
    }
}

/// `441`: "Wrong Credentials".
///
/// > The credentials in the (non-Allocate) request do not match those used to create the allocation.
/// >
/// > [RFC 5766 -- 15. New STUN Error Response Codes]
///
/// [RFC 5766 -- 15. New STUN Error Response Codes]: https://tools.ietf.org/html/rfc5766#section-15
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WrongCredentials;
impl WrongCredentials {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 441;
}
impl From<WrongCredentials> for ErrorCode {
    fn from(_: WrongCredentials) -> Self {
        ErrorCode::new(WrongCredentials::CODEPOINT, "Wrong Credentials".to_owned())
            .expect("never fails")
    }
}

/// `442`: "Unsupported Transport Protocol".
///
/// > The Allocate request asked the server to use a transport protocol between the server and the peer
/// > that the server does not support.  NOTE: This does NOT refer to the transport protocol used in the 5-tuple.
/// >
/// > [RFC 5766 -- 15. New STUN Error Response Codes]
///
/// [RFC 5766 -- 15. New STUN Error Response Codes]: https://tools.ietf.org/html/rfc5766#section-15
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnsupportedTransportProtocol;
impl UnsupportedTransportProtocol {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 442;
}
impl From<UnsupportedTransportProtocol> for ErrorCode {
    fn from(_: UnsupportedTransportProtocol) -> Self {
        ErrorCode::new(
            UnsupportedTransportProtocol::CODEPOINT,
            "Unsupported Transport Protocol".to_owned(),
        )
        .expect("never fails")
    }
}

/// `486`: "Allocation Quota Reached".
///
/// > No more allocations using this username can be created at the present time.
/// >
/// > [RFC 5766 -- 15. New STUN Error Response Codes]
///
/// [RFC 5766 -- 15. New STUN Error Response Codes]: https://tools.ietf.org/html/rfc5766#section-15
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationQuotaReached;
impl AllocationQuotaReached {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 486;
}
impl From<AllocationQuotaReached> for ErrorCode {
    fn from(_: AllocationQuotaReached) -> Self {
        ErrorCode::new(
            AllocationQuotaReached::CODEPOINT,
            "Allocation Quota Reached".to_owned(),
        )
        .expect("never fails")
    }
}

/// `508`: "Insufficient Capacity".
///
/// > The server is unable to carry out the request due to some capacity limit being reached.
/// > In an Allocate response, this could be due to the server having no more relayed transport
/// > addresses available at that time, having none with the requested properties,
/// > or the one that corresponds to the specified reservation token is not available.
/// >
/// > [RFC 5766 -- 15. New STUN Error Response Codes]
///
/// [RFC 5766 -- 15. New STUN Error Response Codes]: https://tools.ietf.org/html/rfc5766#section-15
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InsufficientCapacity;
impl InsufficientCapacity {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 508;
}
impl From<InsufficientCapacity> for ErrorCode {
    fn from(_: InsufficientCapacity) -> Self {
        ErrorCode::new(
            InsufficientCapacity::CODEPOINT,
            "Insufficient Capacity".to_owned(),
        )
        .expect("never fails")
    }
}
