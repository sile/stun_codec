//! [RFC 5766(TURN)][RFC 5766] specific components.
//!
//! [RFC 5766]: https://tools.ietf.org/html/rfc5766
use self::attributes::*;

pub mod attributes;
pub mod errors;
pub mod methods;

define_attribute_enums!(
    Attribute,
    AttributeDecoder,
    AttributeEncoder,
    [
        ChannelNumber,
        Lifetime,
        XorPeerAddress,
        Data,
        XorRelayAddress,
        EvenPort,
        RequestedTransport,
        DontFragment,
        ReservationToken
    ]
);
