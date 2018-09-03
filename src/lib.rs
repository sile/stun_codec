//! Encoders and decoders for [STUN (RFC 5389)][RFC 5389].
//!
//! # Examples
//!
//! ```
//! # extern crate bytecodec;
//! # extern crate stun_codec;
//! use bytecodec::{DecodeExt, EncodeExt};
//! use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};
//! use stun_codec::rfc5389::{attributes::Software, Attribute, Method};
//!
//! # fn main() -> bytecodec::Result<()> {
//! // Creates a message
//! let mut message = Message::new(
//!     MessageClass::Request,
//!     Method::Binding,
//!     TransactionId::new([3; 12]),
//! );
//! message.push_attribute(Attribute::Software(Software::new("foo".to_owned())?));
//!
//! // Encodes the message
//! let mut encoder = MessageEncoder::new();
//! let bytes = encoder.encode_into_bytes(message.clone())?;
//! assert_eq!(
//!     bytes,
//!     [
//!         0, 1, 0, 8, 33, 18, 164, 66, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 128, 34, 0, 3,
//!         102, 111, 111, 0
//!     ]
//! );
//!
//! // Decodes the message
//! let mut decoder = MessageDecoder::<Method, Attribute>::new();
//! let decoded = decoder.decode_from_bytes(&bytes)?;
//! assert_eq!(decoded.class(), message.class());
//! assert_eq!(decoded.method(), message.method());
//! assert_eq!(decoded.transaction_id(), message.transaction_id());
//! assert!(decoded.attributes().eq(message.attributes()));
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [RFC 5389 - Session Traversal Utilities for NAT (STUN)][RFC 5389]
//! - [RFC 5769 - Test Vectors for Session Traversal Utilities for NAT (STUN)][RFC 5769]
//!
//! [RFC 5389]: https://tools.ietf.org/html/rfc5389
//! [RFC 5769]: https://tools.ietf.org/html/rfc5769

#![warn(missing_docs)]

#[macro_use]
extern crate bytecodec;
extern crate byteorder;
extern crate crc;
extern crate hmacsha1;
extern crate md5;
#[macro_use]
extern crate trackable;

pub use attribute::{
    Attribute, AttributeType, RawAttribute, RawAttributeDecoder, RawAttributeEncoder,
};
pub use message::{Message, MessageClass, MessageDecoder, MessageEncoder};
pub use method::Method;
pub use transaction_id::TransactionId;

pub mod net;
pub mod num;
pub mod rfc5389;

mod attribute;
mod constants;
mod message;
mod method;
mod transaction_id;

#[cfg(test)]
mod tests {
    use super::*;
    use bytecodec::{DecodeExt, EncodeExt};
    use rfc5389::{attributes::Software, Attribute, Method};
    use trackable::error::MainError;

    #[test]
    fn it_works() -> Result<(), MainError> {
        let mut message = Message::new(
            MessageClass::Request,
            Method::Binding,
            TransactionId::new([3; 12]),
        );
        message.push_attribute(Attribute::Software(Software::new("foo".to_owned())?));

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message.clone())?;
        assert_eq!(
            bytes,
            [
                0, 1, 0, 8, 33, 18, 164, 66, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 128, 34, 0, 3,
                102, 111, 111, 0
            ]
        );

        let mut decoder = MessageDecoder::<Method, Attribute>::new();
        let decoded = decoder.decode_from_bytes(&bytes)?;
        assert_eq!(decoded.class(), message.class());
        assert_eq!(decoded.method(), message.method());
        assert_eq!(decoded.transaction_id(), message.transaction_id());
        assert!(decoded.attributes().eq(message.attributes()));

        Ok(())
    }
}
