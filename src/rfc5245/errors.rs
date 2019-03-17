//! Error codes that are defined in [RFC 5389 -- 15.6 ERROR-CODE].
//!
//! [RFC 5389 -- 15.6 ERROR-CODE]: https://tools.ietf.org/html/rfc5389#section-15.6
use crate::rfc5389::attributes::ErrorCode;

/// `487`: "Role Conflict".
///
/// > The client asserted an ICE role (controlling or
/// > controlled) that is in conflict with the role of the server.
/// >
/// > [RFC 5245 -- 21.3.  STUN Error Responses]
///
/// [RFC 5245 -- 21.3.  STUN Error Responses]: https://tools.ietf.org/html/rfc5245#section-21.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoleConflict;
impl RoleConflict {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 487;
}
impl From<RoleConflict> for ErrorCode {
    fn from(_: RoleConflict) -> Self {
        ErrorCode::new(RoleConflict::CODEPOINT, "Role Conflict".to_string()).expect("never fails")
    }
}
