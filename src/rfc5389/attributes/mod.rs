use bytecodec::bytes::{BytesDecoder, BytesEncoder, Utf8Decoder, Utf8Encoder};
use bytecodec::combinator::{Collect, PreEncode, Repeat};
use bytecodec::fixnum::{U16beDecoder, U16beEncoder, U32beDecoder, U32beEncoder};
use bytecodec::tuple::{TupleDecoder, TupleEncoder};
use bytecodec::{
    ByteCount, Decode, Encode, EncodeExt, Eos, ErrorKind, Result, SizedEncode, TaggedDecode,
};
use byteorder::{BigEndian, ByteOrder};
use crc::crc32;
use hmacsha1::hmac_sha1;
use md5;
use std;
use std::net::SocketAddr;
use std::vec;

use attribute::{AttrType, AttrValue};
use message::{Message, MessageEncoder, Method};
use rfc5389::errors;
use types::{SocketAddrDecoder, SocketAddrEncoder, SocketAddrValue};

/// The codepoint of the [MappedAddress](struct.MappedAddress.html) attribute.
pub const TYPE_MAPPED_ADDRESS: u16 = 0x0001;

/// The codepoint of the [Username](struct.Username.html) attribute.
pub const TYPE_USERNAME: u16 = 0x0006;

/// The codepoint of the [MessageIntegrity](struct.MessageIntegrity.html) attribute.
pub const TYPE_MESSAGE_INTEGRITY: u16 = 0x0008;

/// The codepoint of the [ErrorCode](struct.ErrorCode.html) attribute.
pub const TYPE_ERROR_CODE: u16 = 0x0009;

/// The codepoint of the [UnknownAttributes](struct.UnknownAttributes.html) attribute.
pub const TYPE_UNKNOWN_ATTRIBUTES: u16 = 0x000A;

/// The codepoint of the [Realm](struct.Realm.html) attribute.
pub const TYPE_REALM: u16 = 0x0014;

/// The codepoint of the [Nonce](struct.Nonce.html) attribute.
pub const TYPE_NONCE: u16 = 0x0015;

/// The codepoint of the [XorMappedAddress](struct.XorMappedAddress.html) attribute.
pub const TYPE_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// The codepoint of the [Software](struct.Software.html) attribute.
pub const TYPE_SOFTWARE: u16 = 0x8022;

/// The codepoint of the [AlternateServer](struct.AlternateServer.html) attribute.
pub const TYPE_ALTERNATE_SERVER: u16 = 0x8023;

/// The codepoint of the [Fingerprint](struct.Fingerprint.html) attribute.
pub const TYPE_FINGERPRINT: u16 = 0x8028;

macro_rules! impl_decode {
    ($decoder:ty, $item:ty, $code:expr, $and_then:expr) => {
        impl Decode for $decoder {
            type Item = $item;

            fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
                track!(self.0.decode(buf, eos))
            }

            fn finish_decoding(&mut self) -> Result<Self::Item> {
                track!(self.0.finish_decoding()).and_then(|item| $and_then(item))
            }

            fn requiring_bytes(&self) -> ByteCount {
                self.0.requiring_bytes()
            }

            fn is_idle(&self) -> bool {
                self.0.is_idle()
            }
        }
        impl TaggedDecode for $decoder {
            type Tag = AttrType;

            fn start_decoding(&mut self, attr_type: Self::Tag) -> Result<()> {
                track_assert_eq!(attr_type.as_u16(), $code, ErrorKind::InvalidInput);
                Ok(())
            }
        }
    };
}

macro_rules! impl_encode {
    ($encoder:ty, $item:ty, $map_from:expr) => {
        impl Encode for $encoder {
            type Item = $item;

            fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
                track!(self.0.encode(buf, eos))
            }

            fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
                track!(self.0.start_encoding($map_from(item)))
            }

            fn requiring_bytes(&self) -> ByteCount {
                self.0.requiring_bytes()
            }

            fn is_idle(&self) -> bool {
                self.0.is_idle()
            }
        }
        impl SizedEncode for $encoder {
            fn exact_requiring_bytes(&self) -> u64 {
                self.0.exact_requiring_bytes()
            }
        }
    };
}

/// `ALTERNATE-SERVER` attribute.
///
/// See [RFC 5389 -- 15.11. ALTERNATE-SERVER]
/// (https://tools.ietf.org/html/rfc5389#section-15.11) about this attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlternateServer(SocketAddr);
impl AlternateServer {
    /// Makes a new `AlternateServer` instance.
    pub fn new(addr: SocketAddr) -> Self {
        AlternateServer(addr)
    }

    /// Returns the alternate address.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl AttrValue for AlternateServer {
    type Decoder = AlternateServerDecoder;
    type Encoder = AlternateServerEncoder;

    fn attr_type(&self) -> AttrType {
        AttrType::new(TYPE_ALTERNATE_SERVER)
    }
}

#[derive(Debug, Default)]
pub struct AlternateServerDecoder(SocketAddrDecoder);
impl_decode!(
    AlternateServerDecoder,
    AlternateServer,
    TYPE_ALTERNATE_SERVER,
    |item| Ok(AlternateServer(item))
);

#[derive(Debug, Default)]
pub struct AlternateServerEncoder(SocketAddrEncoder);
impl_encode!(
    AlternateServerEncoder,
    AlternateServer,
    |item: Self::Item| item.0
);

/// `ERROR-CODE` attribute.
///
/// See [RFC 5389 -- 15.6. ERROR-CODE]
/// (https://tools.ietf.org/html/rfc5389#section-15.6) about this attribute.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ErrorCode {
    code: u16,
    reason_phrase: String, // TODO: Cow
}
impl ErrorCode {
    /// Makes a new `ErrorCode` instance.
    ///
    /// Note that the value of `code` must be in range of `300..600`.
    /// If the value is out-of-range this will return `None`.
    pub fn new(code: u16, reason_phrase: String) -> Option<Self> {
        if 300 <= code && code < 600 {
            Some(ErrorCode {
                code: code,
                reason_phrase: reason_phrase,
            })
        } else {
            None
        }
    }

    /// Returns the code of this error.
    pub fn code(&self) -> u16 {
        self.code
    }

    /// Returns the reason phrase of this error.
    pub fn reason_phrase(&self) -> &str {
        &self.reason_phrase
    }
}
// TODO: impl From<bytecodec::Error>

#[derive(Debug, Default)]
pub struct ErrorCodeDecoder(TupleDecoder<(U32beDecoder, Utf8Decoder)>);
impl_decode!(
    ErrorCodeDecoder,
    ErrorCode,
    TYPE_ERROR_CODE,
    |(value, reason_phrase): (u32, _)| {
        let class = (value >> 8) & 0b111;
        let number = value & 0b11111111;
        track_assert!(3 <= class && class < 6, ErrorKind::InvalidInput);
        track_assert!(number < 100, ErrorKind::InvalidInput);

        let code = (class * 100 + number) as u16;
        Ok(ErrorCode {
            code,
            reason_phrase,
        })
    }
);

#[derive(Debug, Default)]
pub struct ErrorCodeEncoder(TupleEncoder<(U32beEncoder, Utf8Encoder)>);
impl_encode!(ErrorCodeEncoder, ErrorCode, |item: Self::Item| {
    let class = (item.code / 100) as u32;
    let number = (item.code % 100) as u32;
    let value = (class << 8) | number;
    (value, item.reason_phrase)
});

/// `FINGERPRINT` attribute.
///
/// See [RFC 5389 -- 15.5. FINGERPRINT]
/// (https://tools.ietf.org/html/rfc5389#section-15.5) about this attribute.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    crc32: u32,
}
impl Fingerprint {
    /// Makes a new `Fingerprint` instance.
    pub fn new() -> Self {
        Fingerprint { crc32: 0 }
    }

    /// Returns the crc32 value of this instance.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }

    /// Calculates the CRC-32 value of `message` and returns a `Fingerprint` instance containing it.
    pub fn from_message<M: Method, A: AttrValue>(message: Message<M, A>) -> Result<Self> {
        let mut bytes = track!(MessageEncoder::default().encode_into_bytes(message))?;
        let final_len = bytes.len() as u16 - 20 + 8; // Adds `Fingerprint` attribute length
        BigEndian::write_u16(&mut bytes[2..4], final_len);
        let crc32 = crc32::checksum_ieee(&bytes[..]) ^ 0x5354554e;
        Ok(Fingerprint { crc32: crc32 })
    }

    pub fn validate<M: Method, A: AttrValue>(&self, message: Message<M, A>) -> Result<()> {
        let actual = track!(Self::from_message(message))?;
        track_assert_eq!(actual.crc32, self.crc32, ErrorKind::InvalidInput);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct FingerprintDecoder(U32beDecoder);
impl_decode!(FingerprintDecoder, Fingerprint, TYPE_FINGERPRINT, |crc32| {
    Ok(Fingerprint { crc32 })
});

#[derive(Debug, Default)]
pub struct FingerprintEncoder(U32beEncoder);
impl_encode!(FingerprintEncoder, Fingerprint, |item: Self::Item| item
    .crc32);

/// `MAPPED-ADDRESS` attribute.
///
/// See [RFC 5389 -- 15.1. MAPPED-ADDRESS]
/// (https://tools.ietf.org/html/rfc5389#section-15.1) about this attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MappedAddress(SocketAddr);
impl MappedAddress {
    /// Makes a new `MappedAddress` instance.
    pub fn new(addr: SocketAddr) -> Self {
        MappedAddress(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}

#[derive(Debug, Default)]
pub struct MappedAddressDecoder(SocketAddrDecoder);
impl_decode!(
    MappedAddressDecoder,
    MappedAddress,
    TYPE_MAPPED_ADDRESS,
    |item| Ok(MappedAddress(item))
);

#[derive(Debug, Default)]
pub struct MappedAddressEncoder(SocketAddrEncoder);
impl_encode!(MappedAddressEncoder, MappedAddress, |item: Self::Item| item
    .0);

/// `MESSAGE-INTEGRITY` attribute.
///
/// See [RFC 5389 -- 15.3. MESSAGE-INTEGRITY]
/// (https://tools.ietf.org/html/rfc5389#section-15.4) about this attribute.
///
/// # TODO
///
/// - Support SASLprep
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageIntegrity {
    hmac_sha1: [u8; 20],
    preceding_message_bytes: Vec<u8>,
}
impl MessageIntegrity {
    /// Makes a new `MessageIntegrity` instance for short-term credentials.
    pub fn new_short_term_credential<M, A>(message: Message<M, A>, password: &str) -> Result<Self>
    where
        M: Method,
        A: AttrValue,
    {
        let key = password.as_bytes();
        let preceding_message_bytes = track!(Self::message_into_bytes(message))?;
        let hmac_sha1 = hmac_sha1(key, &preceding_message_bytes);
        Ok(MessageIntegrity {
            hmac_sha1,
            preceding_message_bytes,
        })
    }

    /// Makes a new `MessageIntegrity` instance for long-term credentials.
    pub fn new_long_term_credential<M, A>(
        message: Message<M, A>,
        username: &Username,
        realm: &Realm,
        password: &str,
    ) -> Result<Self>
    where
        M: Method,
        A: AttrValue,
    {
        let key =
            md5::compute(format!("{}:{}:{}", username.name(), realm.text(), password).as_bytes());
        let preceding_message_bytes = track!(Self::message_into_bytes(message))?;
        let hmac_sha1 = hmac_sha1(&key.0[..], &preceding_message_bytes);
        Ok(MessageIntegrity {
            hmac_sha1,
            preceding_message_bytes,
        })
    }

    /// Checks whether this has the valid short-term credential for `password`.
    pub fn check_short_term_credential(
        &self,
        password: &str,
    ) -> std::result::Result<(), ErrorCode> {
        let key = password.as_bytes();
        let expected = hmac_sha1(key, &self.preceding_message_bytes);
        if self.hmac_sha1 == expected {
            Ok(())
        } else {
            Err(errors::Unauthorized.into())
        }
    }

    /// Checks whether this has the valid long-term credential for `password`.
    pub fn check_long_term_credential(
        &self,
        username: &Username,
        realm: &Realm,
        password: &str,
    ) -> std::result::Result<(), ErrorCode> {
        let key =
            md5::compute(format!("{}:{}:{}", username.name(), realm.text(), password).as_bytes());
        let expected = hmac_sha1(&key.0[..], &self.preceding_message_bytes);
        if self.hmac_sha1 == expected {
            Ok(())
        } else {
            Err(errors::Unauthorized.into())
        }
    }

    /// Returns the HMAC-SHA1 of this instance.
    pub fn hmac_sha1(&self) -> [u8; 20] {
        self.hmac_sha1
    }

    // TODO: name
    pub fn validate<M: Method, A: AttrValue>(&mut self, message: Message<M, A>) -> Result<()> {
        self.preceding_message_bytes = track!(Self::message_into_bytes(message))?;
        Ok(())
    }

    fn message_into_bytes<M: Method, A: AttrValue>(message: Message<M, A>) -> Result<Vec<u8>> {
        let mut bytes = track!(MessageEncoder::default().encode_into_bytes(message))?;
        let adjusted_len = bytes.len() - 20 /*msg header*/+ 4 /*attr header*/ + 20 /*hmac*/;
        BigEndian::write_u16(&mut bytes[2..4], adjusted_len as u16);
        Ok(bytes)
    }
}

#[derive(Debug, Default)]
pub struct MessageIntegrityDecoder(BytesDecoder<[u8; 20]>);
impl_decode!(
    MessageIntegrityDecoder,
    MessageIntegrity,
    TYPE_MESSAGE_INTEGRITY,
    |hmac_sha1| Ok(MessageIntegrity {
        hmac_sha1,
        preceding_message_bytes: Vec::new() // TODO: note
    })
);

#[derive(Debug, Default)]
pub struct MessageIntegrityEncoder(BytesEncoder<[u8; 20]>);
impl_encode!(
    MessageIntegrityEncoder,
    MessageIntegrity,
    |item: Self::Item| item.hmac_sha1
);

/// `NONCE` attribute.
///
/// See [RFC 5389 -- 15.8. NONCE]
/// (https://tools.ietf.org/html/rfc5389#section-15.8) about this attribute.
///
/// # TODO
///
/// - Support [RFC 3261] and [RFC 2617]
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce {
    value: String,
}
impl Nonce {
    /// Makes a new `Nonce` instance.
    ///
    /// The length of `value` must be less than `128` characters.
    /// If it is too long, this will return `None`.
    pub fn new(value: String) -> Option<Self> {
        if value.chars().count() < 128 {
            Some(Nonce { value: value })
        } else {
            None
        }
    }

    /// Returns the value of this instance.
    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Default)]
pub struct NonceDecoder(Utf8Decoder);
impl_decode!(NonceDecoder, Nonce, TYPE_NONCE, |value| Ok(Nonce { value })); // TODO: length check

#[derive(Debug, Default)]
pub struct NonceEncoder(Utf8Encoder);
impl_encode!(NonceEncoder, Nonce, |item: Self::Item| item.value);

/// `REALM` attribute.
///
/// See [RFC 5389 -- 15.7. REALM]
/// (https://tools.ietf.org/html/rfc5389#section-15.7) about this attribute.
///
/// # TODO
///
/// - Support SASLprep [RFC 4013]
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Realm {
    text: String,
}
impl Realm {
    /// Makes a new `Realm` instance.
    ///
    /// The length of `text` must be less than `128` characters.
    /// If it is too long, this will return `None`.
    pub fn new(text: String) -> Option<Self> {
        if text.chars().count() < 128 {
            Some(Realm { text: text })
        } else {
            None
        }
    }

    /// Returns the text of this instance.
    pub fn text(&self) -> &str {
        &self.text
    }
}

#[derive(Debug, Default)]
pub struct RealmDecoder(Utf8Decoder);
impl_decode!(RealmDecoder, Realm, TYPE_REALM, |text| Ok(Realm { text })); // TODO: length check

#[derive(Debug, Default)]
pub struct RealmEncoder(Utf8Encoder);
impl_encode!(RealmEncoder, Realm, |item: Self::Item| item.text);

/// `SOFTWARE` attribute.
///
/// See [RFC 5389 -- 15.10. SOFTWARE]
/// (https://tools.ietf.org/html/rfc5389#section-15.10) about this attribute.
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Software {
    description: String,
}
impl Software {
    /// Makes a new `Software` instance.
    ///
    /// The length of `description` must be less than `128` characters.
    /// If it is too long, this will return `None`.
    pub fn new(description: String) -> Option<Self> {
        if description.chars().count() < 128 {
            Some(Software {
                description: description,
            })
        } else {
            None
        }
    }

    /// Returns the description of this instance.
    pub fn description(&self) -> &str {
        &self.description
    }
}

#[derive(Debug, Default)]
pub struct SoftwareDecoder(Utf8Decoder);
impl_decode!(SoftwareDecoder, Software, TYPE_SOFTWARE, |description| Ok(
    Software { description }
)); // TODO: length check

#[derive(Debug, Default)]
pub struct SoftwareEncoder(Utf8Encoder);
impl_encode!(SoftwareEncoder, Software, |item: Self::Item| item
    .description);

/// `UNKNOWN-ATTRIBUTES` attribute.
///
/// See [RFC 5389 -- 15.9. UNKNOWN-ATTRIBUTES]
/// (https://tools.ietf.org/html/rfc5389#section-15.9) about this attribute.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownAttributes {
    unknowns: Vec<AttrType>,
}
impl UnknownAttributes {
    /// Makes a new `UnknownAttributes` instance.
    pub fn new(unknowns: Vec<AttrType>) -> Self {
        UnknownAttributes { unknowns: unknowns }
    }

    /// Returns the unknown attribute types of this instance.
    pub fn unknowns(&self) -> &[AttrType] {
        &self.unknowns
    }
}

#[derive(Debug, Default)]
pub struct UnknownAttributesDecoder(Collect<U16beDecoder, Vec<u16>>); // TODO: TypeDecoder
impl_decode!(
    UnknownAttributesDecoder,
    UnknownAttributes,
    TYPE_UNKNOWN_ATTRIBUTES,
    |vs: Vec<u16>| Ok(UnknownAttributes {
        unknowns: vs.into_iter().map(AttrType::new).collect()
    })
);

#[derive(Debug, Default)]
pub struct UnknownAttributesEncoder(PreEncode<Repeat<U16beEncoder, vec::IntoIter<u16>>>); // TODO
impl_encode!(
    UnknownAttributesEncoder,
    UnknownAttributes,
    |item: Self::Item| item
        .unknowns
        .into_iter()
        .map(|ty| ty.as_u16())
        .collect::<Vec<_>>()
        .into_iter()
);

/// `USERNAME` attribute.
///
/// See [RFC 5389 -- 15.3. USERNAME]
/// (https://tools.ietf.org/html/rfc5389#section-15.3) about this attribute.
///
/// # TODO
///
/// - Support SASLprep [RFC 4013]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Username {
    name: String,
}
impl Username {
    /// Makes a new `Username` instance.
    ///
    /// The length of `name` must be less then `513` bytes.
    /// If it is too long, this will return `None`.
    pub fn new(name: String) -> Option<Self> {
        if name.len() < 513 {
            Some(Username { name: name })
        } else {
            None
        }
    }

    /// Returns the name of this instance.
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Default)]
pub struct UsernameDecoder(Utf8Decoder);
impl_decode!(UsernameDecoder, Username, TYPE_USERNAME, |name| Ok(
    Username { name }
)); // TODO: length check

#[derive(Debug, Default)]
pub struct UsernameEncoder(Utf8Encoder);
impl_encode!(UsernameEncoder, Username, |item: Self::Item| item.name);

/// `XOR-MAPPED-ADDRESS` attribute.
///
/// See [RFC 5389 -- 15.2. XOR-MAPPED-ADDRESS]
/// (https://tools.ietf.org/html/rfc5389#section-15.2) about this attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XorMappedAddress(SocketAddr);
impl XorMappedAddress {
    /// Makes a new `XorMappedAddress` instance.
    pub fn new(addr: SocketAddr) -> Self {
        XorMappedAddress(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }

    pub fn pre_encode<M: Method, A: AttrValue>(&mut self, message: &Message<M, A>) -> Result<()> {
        self.0 = SocketAddrValue::new(self.0)
            .xor(message.transaction_id())
            .address();
        Ok(())
    }

    pub fn post_decode<M: Method, A: AttrValue>(&mut self, message: &Message<M, A>) -> Result<()> {
        self.0 = SocketAddrValue::new(self.0)
            .xor(message.transaction_id())
            .address();
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct XorMappedAddressDecoder(SocketAddrDecoder);
impl_decode!(
    XorMappedAddressDecoder,
    XorMappedAddress,
    TYPE_XOR_MAPPED_ADDRESS,
    |item| Ok(XorMappedAddress(item))
);

#[derive(Debug, Default)]
pub struct XorMappedAddressEncoder(SocketAddrEncoder);
impl_encode!(
    XorMappedAddressEncoder,
    XorMappedAddress,
    |item: Self::Item| item.0
);
