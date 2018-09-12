//! [RFC 5389(STUN)][RFC 5389] specific components.
//!
//! [RFC 5389]: https://tools.ietf.org/html/rfc5389
use self::attributes::*;

pub mod attributes;
pub mod errors;
pub mod methods;

define_attribute_enums!(
    Attribute,
    AttributeDecoder,
    AttributeEncoder,
    [
        MappedAddress,
        Username,
        MessageIntegrity,
        ErrorCode,
        UnknownAttributes,
        Realm,
        Nonce,
        XorMappedAddress,
        Software,
        AlternateServer,
        Fingerprint
    ]
);
