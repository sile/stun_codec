//! Encoders and decoders for [STUN (RFC 5389)][RFC 5389] and its extensions.
//!
//! # Examples
//!
//! ```
//! # extern crate bytecodec;
//! # extern crate stun_codec;
//! use bytecodec::{DecodeExt, EncodeExt, Error};
//! use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};
//! use stun_codec::rfc5389::{attributes::Software, methods::BINDING, Attribute};
//!
//! # fn main() -> bytecodec::Result<()> {
//! // Creates a message
//! let mut message = Message::new(MessageClass::Request, BINDING, TransactionId::new([3; 12]));
//! message.add_attribute(Attribute::Software(Software::new("foo".to_owned())?));
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
//! let mut decoder = MessageDecoder::<Attribute>::new();
//! let decoded = decoder.decode_from_bytes(&bytes)?.map_err(Error::from)?;
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
pub use message::{
    BrokenMessage, DecodedMessage, Message, MessageClass, MessageDecoder, MessageEncoder,
};
pub use method::Method;
pub use transaction_id::TransactionId;

#[macro_use]
mod macros;

pub mod net;
pub mod rfc5389;
pub mod rfc5766;

mod attribute;
mod constants;
mod message;
mod method;
mod transaction_id;

#[cfg(test)]
mod tests {
    use bytecodec::{DecodeExt, EncodeExt, Error};
    use trackable::error::MainError;

    use super::*;
    use rfc5389::attributes::Software;
    use rfc5389::methods::BINDING;
    use rfc5389::Attribute;

    macro_rules! get_attr {
        ($message:expr, $attr:ident) => {
            $message
                .attributes()
                .filter_map(|a| {
                    if let Attribute::$attr(a) = a {
                        Some(a)
                    } else {
                        None
                    }
                })
                .nth(0)
                .unwrap()
        };
    }

    #[test]
    fn it_works() -> Result<(), MainError> {
        let mut message = Message::new(MessageClass::Request, BINDING, TransactionId::new([3; 12]));
        message.add_attribute(Attribute::Software(Software::new("foo".to_owned())?));

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message.clone())?;
        assert_eq!(
            bytes,
            [
                0, 1, 0, 8, 33, 18, 164, 66, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 128, 34, 0, 3,
                102, 111, 111, 0
            ]
        );

        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded = decoder.decode_from_bytes(&bytes)?.map_err(Error::from)?;
        assert_eq!(decoded.class(), message.class());
        assert_eq!(decoded.method(), message.method());
        assert_eq!(decoded.transaction_id(), message.transaction_id());
        assert!(decoded.attributes().eq(message.attributes()));

        Ok(())
    }

    #[test]
    fn rfc5769_2_1_sample_request() -> Result<(), MainError> {
        let input = [
            0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e,
            0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24,
            0x00, 0x04, 0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1,
            0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68,
            0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c,
            0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5,
            0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
        ];
        let mut decoder = MessageDecoder::<Attribute>::new();
        let message = decoder.decode_from_bytes(&input)?.map_err(Error::from)?;
        assert_eq!(message.class(), MessageClass::Request);

        let mut encoder = MessageEncoder::new();
        assert_eq!(encoder.encode_into_bytes(message.clone())?, &input[..]);

        // TEST: `MessageIntegrity`
        let password = "VOkJxbRl1RmTxUk/WvJxBt";
        get_attr!(message, MessageIntegrity)
            .check_short_term_credential(password)
            .unwrap();

        // TEST: `Fingerprint`
        assert_eq!(get_attr!(message, Fingerprint).crc32(), 0xe57a3bcf);

        Ok(())
    }

    #[test]
    fn rfc5769_2_2_sample_ipv4_response() -> Result<(), MainError> {
        let input = [
            0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99,
            0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b,
            0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
        ];
        let mut decoder = MessageDecoder::<Attribute>::new();
        let message = decoder.decode_from_bytes(&input)?.map_err(Error::from)?;
        assert_eq!(message.class(), MessageClass::SuccessResponse);

        let mut encoder = MessageEncoder::new();
        assert_eq!(encoder.encode_into_bytes(message.clone())?, &input[..]);

        // TEST: `MessageIntegrity`
        let password = "VOkJxbRl1RmTxUk/WvJxBt";
        get_attr!(message, MessageIntegrity)
            .check_short_term_credential(password)
            .unwrap();

        // TEST: `XorMappedAddress` (IPv4)
        assert_eq!(
            get_attr!(message, XorMappedAddress).address(),
            "192.0.2.1:32853".parse().unwrap()
        );

        // TEST: `Fingerprint`
        assert_eq!(get_attr!(message, Fingerprint).crc32(), 0xc07d4c96);

        Ok(())
    }

    #[test]
    fn rfc5769_2_3_sample_ipv6_response() -> Result<(), MainError> {
        let input = [
            0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02,
            0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5,
            0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6,
            0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41,
            0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c,
        ];
        let mut decoder = MessageDecoder::<Attribute>::new();
        let message = decoder.decode_from_bytes(&input)?.map_err(Error::from)?;
        assert_eq!(message.class(), MessageClass::SuccessResponse);

        let mut encoder = MessageEncoder::new();
        assert_eq!(encoder.encode_into_bytes(message.clone())?, &input[..]);

        // TEST: `MessageIntegrity`
        let password = "VOkJxbRl1RmTxUk/WvJxBt";
        get_attr!(message, MessageIntegrity)
            .check_short_term_credential(password)
            .unwrap();

        // TEST: `XorMappedAddress` (IPv6)
        assert_eq!(
            get_attr!(message, XorMappedAddress).address(),
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                .parse()
                .unwrap()
        );

        // TEST: `Fingerprint`
        assert_eq!(get_attr!(message, Fingerprint).crc32(), 0xc8fb0b4c);

        Ok(())
    }

    #[test]
    fn rfc5769_2_4_sample_request_with_long_term_authentication() -> Result<(), MainError> {
        let input = [
            0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33, 0xc6, 0xad,
            0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e, 0x00, 0x06, 0x00, 0x12, 0xe3, 0x83, 0x9e, 0xe3,
            0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf, 0xe3, 0x82, 0xb9,
            0x00, 0x00, 0x00, 0x15, 0x00, 0x1c, 0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39,
            0x35, 0x34, 0x64, 0x36, 0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54,
            0x76, 0x79, 0x36, 0x34, 0x73, 0x41, 0x00, 0x14, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x08, 0x00, 0x14, 0xf6, 0x70,
            0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02, 0xb8, 0xe0, 0x71, 0x2e, 0x85, 0xc9, 0xa2,
            0x8c, 0xa8, 0x96, 0x66,
        ];
        let mut decoder = MessageDecoder::<Attribute>::new();
        let message = decoder.decode_from_bytes(&input)?.map_err(Error::from)?;
        assert_eq!(message.class(), MessageClass::Request);

        let mut encoder = MessageEncoder::new();
        assert_eq!(encoder.encode_into_bytes(message.clone())?, &input[..]);

        // TEST: `MessageIntegrity`
        let uesrname = get_attr!(message, Username);
        let realm = get_attr!(message, Realm);
        let password = "TheMatrIX"; // TODO: Test before SASLprep version
        get_attr!(message, MessageIntegrity)
            .check_long_term_credential(&uesrname, &realm, password)
            .unwrap();

        Ok(())
    }
}
