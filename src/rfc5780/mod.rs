//! [RFC 5780(NAT Behavior Discovery)][RFC 5780] specific components.
//!
//! [RFC 5780]: https://tools.ietf.org/html/rfc5780
use self::attributes::*;

pub mod attributes;

define_attribute_enums!(
    Attribute,
    AttributeDecoder,
    AttributeEncoder,
    [ChangeRequest, ResponseOrigin, ResponsePort, OtherAddress]
);
