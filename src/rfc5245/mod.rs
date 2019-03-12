//! [RFC 5245(ICE)][RFC 5245] specific components.
//!
//! [RFC 5245]: https://tools.ietf.org/html/rfc5245
use self::attributes::*;

pub mod attributes;
pub mod errors;

define_attribute_enums!(
    Attribute,
    AttributeDecoder,
    AttributeEncoder,
    [Priority, UseCandidate, IceControlled, IceControlling]
);
