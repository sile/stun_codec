//! Error codes that are defined in RFC 8016.
use crate::rfc5389::attributes::ErrorCode;

/// `405`: "Mobility Forbidden".
///
/// >  405 (Mobility Forbidden): Mobility request was valid but cannot be performed due to administrative or similar restrictions.
/// >
/// > [RFC 8016 -- 3.4]
///
/// [RFC 8016 -- 3.4]: https://www.rfc-editor.org/rfc/rfc8016.html#section-3.4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MobilityForbidden;
impl MobilityForbidden {
    /// The codepoint of the error.
    pub const CODEPOINT: u16 = 405;
}
impl From<MobilityForbidden> for ErrorCode {
    fn from(_: MobilityForbidden) -> Self {
        ErrorCode::new(
            MobilityForbidden::CODEPOINT,
            "Mobility Forbidden".to_owned(),
        )
        .expect("never fails")
    }
}
