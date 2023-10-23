//! Attributes that are defined in [RFC 5389].
//!
//! [RFC 5389]: https://tools.ietf.org/html/rfc5389
use crate::attribute::{Attribute, AttributeType};
use crate::message::{Message, MessageEncoder};
use crate::net::{socket_addr_xor, SocketAddrDecoder, SocketAddrEncoder};
use crate::rfc5389::errors;
use bytecodec::bytes::{BytesEncoder, CopyableBytesDecoder, Utf8Decoder, Utf8Encoder};
use bytecodec::combinator::{Collect, PreEncode, Repeat};
use bytecodec::fixnum::{U16beDecoder, U16beEncoder, U32beDecoder, U32beEncoder};
use bytecodec::tuple::{TupleDecoder, TupleEncoder};
use bytecodec::{
    ByteCount, Decode, Encode, EncodeExt, Eos, Error, ErrorKind, Result, SizedEncode,
    TryTaggedDecode,
};
use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::borrow::Cow;
use std::net::SocketAddr;
use std::vec;

macro_rules! impl_decode {
    ($decoder:ty, $item:ident, $and_then:expr) => {
        impl Decode for $decoder {
            type Item = $item;

            fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
                track!(self.0.decode(buf, eos))
            }

            fn finish_decoding(&mut self) -> Result<Self::Item> {
                track!(self.0.finish_decoding()).and_then($and_then)
            }

            fn requiring_bytes(&self) -> ByteCount {
                self.0.requiring_bytes()
            }

            fn is_idle(&self) -> bool {
                self.0.is_idle()
            }
        }
        impl TryTaggedDecode for $decoder {
            type Tag = AttributeType;

            fn try_start_decoding(&mut self, attr_type: Self::Tag) -> Result<bool> {
                Ok(attr_type.as_u16() == $item::CODEPOINT)
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

            #[allow(clippy::redundant_closure_call)]
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
/// See [RFC 5389 -- 15.11. ALTERNATE-SERVER] about this attribute.
///
/// [RFC 5389 -- 15.11. ALTERNATE-SERVER]: https://tools.ietf.org/html/rfc5389#section-15.11
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AlternateServer(SocketAddr);
impl AlternateServer {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x8023;

    /// Makes a new `AlternateServer` instance.
    pub fn new(addr: SocketAddr) -> Self {
        AlternateServer(addr)
    }

    /// Returns the alternate address.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl Attribute for AlternateServer {
    type Decoder = AlternateServerDecoder;
    type Encoder = AlternateServerEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`AlternateServer`] decoder.
#[derive(Debug, Default)]
pub struct AlternateServerDecoder(SocketAddrDecoder);
impl AlternateServerDecoder {
    /// Makes a new `AlternateServerDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(AlternateServerDecoder, AlternateServer, |item| Ok(
    AlternateServer(item)
));

/// [`AlternateServer`] encoder.
#[derive(Debug, Default)]
pub struct AlternateServerEncoder(SocketAddrEncoder);
impl AlternateServerEncoder {
    /// Makes a new `AlternateServerEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    AlternateServerEncoder,
    AlternateServer,
    |item: Self::Item| item.0
);

/// `ERROR-CODE` attribute.
///
/// See [RFC 5389 -- 15.6. ERROR-CODE] about this attribute.
///
/// [RFC 5389 -- 15.6. ERROR-CODE]: https://tools.ietf.org/html/rfc5389#section-15.6
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ErrorCode {
    code: u16,
    reason_phrase: String,
}
impl ErrorCode {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0009;

    /// Makes a new `ErrorCode` instance.
    ///
    /// # Errors
    ///
    /// Note that the value of `code` must be in range of `300..600`.
    /// If the value is out-of-range this will return an `ErrorKind::InvalidInput` error.
    pub fn new(code: u16, reason_phrase: String) -> Result<Self> {
        track_assert!((300..600).contains(&code), ErrorKind::InvalidInput; code, reason_phrase);
        Ok(ErrorCode {
            code,
            reason_phrase,
        })
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
impl Attribute for ErrorCode {
    type Decoder = ErrorCodeDecoder;
    type Encoder = ErrorCodeEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}
impl From<Error> for ErrorCode {
    fn from(f: Error) -> Self {
        match *f.kind() {
            ErrorKind::InvalidInput => errors::BadRequest.into(),
            _ => errors::ServerError.into(),
        }
    }
}

/// [`ErrorCode`] decoder.
#[derive(Debug, Default)]
pub struct ErrorCodeDecoder(TupleDecoder<(U32beDecoder, Utf8Decoder)>);
impl ErrorCodeDecoder {
    /// Makes a new `ErrorCodeDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(ErrorCodeDecoder, ErrorCode, |(value, reason_phrase): (
    u32,
    _
)| {
    let class = (value >> 8) & 0b111;
    let number = value & 0b1111_1111;
    track_assert!((3..6).contains(&class), ErrorKind::InvalidInput);
    track_assert!(number < 100, ErrorKind::InvalidInput);

    let code = (class * 100 + number) as u16;
    Ok(ErrorCode {
        code,
        reason_phrase,
    })
});

/// [`ErrorCode`] encoder.
#[derive(Debug, Default)]
pub struct ErrorCodeEncoder(TupleEncoder<(U32beEncoder, Utf8Encoder)>);
impl ErrorCodeEncoder {
    /// Makes a new `ErrorCodeEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(ErrorCodeEncoder, ErrorCode, |item: Self::Item| {
    let class = u32::from(item.code / 100);
    let number = u32::from(item.code % 100);
    let value = (class << 8) | number;
    (value, item.reason_phrase)
});

/// `FINGERPRINT` attribute.
///
/// See [RFC 5389 -- 15.5. FINGERPRINT] about this attribute.
///
/// [RFC 5389 -- 15.5. FINGERPRINT]: https://tools.ietf.org/html/rfc5389#section-15.5
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    crc32: u32,
}
impl Fingerprint {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x8028;

    /// Calculates the CRC-32 value of `message` and returns a `Fingerprint` instance containing it.
    pub fn new<A: Attribute>(message: &Message<A>) -> Result<Self> {
        let mut bytes = track!(MessageEncoder::default().encode_into_bytes(message.clone()))?;
        let final_len = bytes.len() as u16 - 20 + 8; // Adds `Fingerprint` attribute length
        BigEndian::write_u16(&mut bytes[2..4], final_len);
        let crc32 = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(&bytes[..]) ^ 0x5354_554e;
        Ok(Fingerprint { crc32 })
    }

    /// Returns the crc32 value of this instance.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }
}
impl Attribute for Fingerprint {
    type Decoder = FingerprintDecoder;
    type Encoder = FingerprintEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }

    fn after_decode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        let actual = track!(Self::new(message))?;
        track_assert_eq!(actual.crc32, self.crc32, ErrorKind::InvalidInput);
        Ok(())
    }
}

/// [`Fingerprint`] decoder.
#[derive(Debug, Default)]
pub struct FingerprintDecoder(U32beDecoder);
impl FingerprintDecoder {
    /// Makes a new `FingerprintDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(FingerprintDecoder, Fingerprint, |crc32| Ok(Fingerprint {
    crc32
}));

/// [`Fingerprint`] encoder.
#[derive(Debug, Default)]
pub struct FingerprintEncoder(U32beEncoder);
impl FingerprintEncoder {
    /// Makes a new `FingerprintEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(FingerprintEncoder, Fingerprint, |item: Self::Item| item
    .crc32);

/// `MAPPED-ADDRESS` attribute.
///
/// See [RFC 5389 -- 15.1. MAPPED-ADDRESS] about this attribute.
///
/// [RFC 5389 -- 15.1. MAPPED-ADDRESS]: https://tools.ietf.org/html/rfc5389#section-15.1
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MappedAddress(SocketAddr);
impl MappedAddress {
    /// The codepoint of the tyep of the attribute.
    pub const CODEPOINT: u16 = 0x0001;

    /// Makes a new `MappedAddress` instance.
    pub fn new(addr: SocketAddr) -> Self {
        MappedAddress(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl Attribute for MappedAddress {
    type Decoder = MappedAddressDecoder;
    type Encoder = MappedAddressEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`MappedAddress`] decoder.
#[derive(Debug, Default)]
pub struct MappedAddressDecoder(SocketAddrDecoder);
impl MappedAddressDecoder {
    /// Makes a new `MappedAddressDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(MappedAddressDecoder, MappedAddress, |item| Ok(
    MappedAddress(item)
));

/// [`MappedAddress`] encoder.
#[derive(Debug, Default)]
pub struct MappedAddressEncoder(SocketAddrEncoder);
impl MappedAddressEncoder {
    /// Makes a new `MappedAddressEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(MappedAddressEncoder, MappedAddress, |item: Self::Item| item
    .0);

/// `MESSAGE-INTEGRITY` attribute.
///
/// See [RFC 5389 -- 15.3. MESSAGE-INTEGRITY] about this attribute.
///
/// [RFC 5389 -- 15.3. MESSAGE-INTEGRITY]: https://tools.ietf.org/html/rfc5389#section-15.4
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
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0008;

    /// utility function for creating HMAC-SHA1 signatures
    fn generate_hmac_token(key: &[u8], message: &[u8]) -> [u8; 20] {
        // Create the hasher with the key. We can use expect for Hmac algorithms as they allow arbitrary key sizes.
        let mut hasher: Hmac<Sha1> =
            Mac::new_from_slice(key).expect("HMAC algoritms can take keys of any size");

        // hash the message
        hasher.update(message);

        // finalize the hash and convert to a static array
        hasher.finalize().into_bytes().into()
    }

    /// Makes a new `MessageIntegrity` instance for short-term credentials.
    pub fn new_short_term_credential<A>(message: &Message<A>, password: &str) -> Result<Self>
    where
        A: Attribute,
    {
        let key = password.as_bytes();
        let preceding_message_bytes = track!(Self::message_into_bytes(message.clone()))?;
        let hmac_sha1 = Self::generate_hmac_token(key, &preceding_message_bytes);
        Ok(MessageIntegrity {
            hmac_sha1,
            preceding_message_bytes,
        })
    }

    /// Makes a new `MessageIntegrity` instance for long-term credentials.
    pub fn new_long_term_credential<A>(
        message: &Message<A>,
        username: &Username,
        realm: &Realm,
        password: &str,
    ) -> Result<Self>
    where
        A: Attribute,
    {
        let key =
            md5::compute(format!("{}:{}:{}", username.name(), realm.text(), password).as_bytes());
        let preceding_message_bytes = track!(Self::message_into_bytes(message.clone()))?;
        let hmac_sha1 = Self::generate_hmac_token(&key.0[..], &preceding_message_bytes);
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
        let expected = Self::generate_hmac_token(key, &self.preceding_message_bytes);
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
        let expected = Self::generate_hmac_token(&key.0[..], &self.preceding_message_bytes);
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

    fn message_into_bytes<A: Attribute>(message: Message<A>) -> Result<Vec<u8>> {
        let mut bytes = track!(MessageEncoder::default().encode_into_bytes(message))?;
        let adjusted_len = bytes.len() - 20 /*msg header*/+ 4 /*attr header*/ + 20 /*hmac*/;
        BigEndian::write_u16(&mut bytes[2..4], adjusted_len as u16);
        Ok(bytes)
    }
}
impl Attribute for MessageIntegrity {
    type Decoder = MessageIntegrityDecoder;
    type Encoder = MessageIntegrityEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }

    fn after_decode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        self.preceding_message_bytes = track!(Self::message_into_bytes(message.clone()))?;
        Ok(())
    }
}

/// [`MessageIntegrity`] decoder.
#[derive(Debug, Default)]
pub struct MessageIntegrityDecoder(CopyableBytesDecoder<[u8; 20]>);
impl MessageIntegrityDecoder {
    /// Makes a new `MessageIntegrityDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(MessageIntegrityDecoder, MessageIntegrity, |hmac_sha1| Ok(
    MessageIntegrity {
        hmac_sha1,
        preceding_message_bytes: Vec::new() // dummy
    }
));

/// [`MessageIntegrity`] encoder.
#[derive(Debug, Default)]
pub struct MessageIntegrityEncoder(BytesEncoder<[u8; 20]>);
impl MessageIntegrityEncoder {
    /// Makes a new `MessageIntegrityEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    MessageIntegrityEncoder,
    MessageIntegrity,
    |item: Self::Item| item.hmac_sha1
);

/// `NONCE` attribute.
///
/// See [RFC 5389 -- 15.8. NONCE] about this attribute.
///
/// [RFC 5389 -- 15.8. NONCE]: https://tools.ietf.org/html/rfc5389#section-15.8
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
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0015;

    /// Makes a new `Nonce` instance.
    ///
    /// # Errors
    ///
    /// The length of `value` must be less than `128` characters.
    /// If it is too long, this will return an `ErrorKind::InvalidInput` error.
    pub fn new(value: String) -> Result<Self> {
        track_assert!(value.chars().count() < 128, ErrorKind::InvalidInput; value);
        Ok(Nonce { value })
    }

    /// Returns the value of this instance.
    pub fn value(&self) -> &str {
        &self.value
    }
}
impl Attribute for Nonce {
    type Decoder = NonceDecoder;
    type Encoder = NonceEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`Nonce`] decoder.
#[derive(Debug, Default)]
pub struct NonceDecoder(Utf8Decoder);
impl NonceDecoder {
    /// Makes a new `NonceDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(NonceDecoder, Nonce, Nonce::new);

/// [`Nonce`] encoder.
#[derive(Debug, Default)]
pub struct NonceEncoder(Utf8Encoder);
impl NonceEncoder {
    /// Makes a new `NonceEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(NonceEncoder, Nonce, |item: Self::Item| item.value);

/// `REALM` attribute.
///
/// See [RFC 5389 -- 15.7. REALM] about this attribute.
///
/// [RFC 5389 -- 15.7. REALM]: https://tools.ietf.org/html/rfc5389#section-15.7
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
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0014;

    /// Makes a new `Realm` instance.
    ///
    /// # Errors
    ///
    /// The length of `text` must be less than `128` characters.
    /// If it is too long, this will return an `ErrorKind::InvalidInput` error.
    pub fn new(text: String) -> Result<Self> {
        track_assert!( text.chars().count() < 128, ErrorKind::InvalidInput; text);
        Ok(Realm { text })
    }

    /// Returns the text of this instance.
    pub fn text(&self) -> &str {
        &self.text
    }
}
impl Attribute for Realm {
    type Decoder = RealmDecoder;
    type Encoder = RealmEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`Realm`] decoder.
#[derive(Debug, Default)]
pub struct RealmDecoder(Utf8Decoder);
impl RealmDecoder {
    /// Makes a new `RealmDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(RealmDecoder, Realm, Realm::new);

/// [`Realm`] encoder.
#[derive(Debug, Default)]
pub struct RealmEncoder(Utf8Encoder);
impl RealmEncoder {
    /// Makes a new `RealmEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(RealmEncoder, Realm, |item: Self::Item| item.text);

/// `SOFTWARE` attribute.
///
/// See [RFC 5389 -- 15.10. SOFTWARE] about this attribute.
///
/// [RFC 5389 -- 15.10. SOFTWARE]: https://tools.ietf.org/html/rfc5389#section-15.10
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Software {
    description: Cow<'static, str>,
}
impl Software {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x8022;

    /// Makes a new `Software` instance.
    ///
    /// # Errors
    ///
    /// The length of `description` must be less than `128` characters.
    /// If it is too long, this will return an `ErrorKind::InvalidInput` error.
    pub fn new(description: String) -> Result<Self> {
        track_assert!(description.chars().count() < 128, ErrorKind::InvalidInput; description);
        Ok(Software {
            description: description.into(),
        })
    }

    /// Makes a new `Software` instance from a static string.
    ///
    /// This function is const, so you can create this in a const context.
    ///
    /// # Panics
    ///
    /// The length of `description` must be less than `128` characters.
    /// Panics if the string is longer.
    pub const fn new_static(description: &'static str) -> Self {
        if description.len() >= 128 {
            panic!("Description for `Software` cannot be longer than 128 characters.");
        }
        Self {
            description: Cow::Borrowed(description),
        }
    }

    /// Returns the description of this instance.
    pub fn description(&self) -> &str {
        &self.description
    }
}
impl Attribute for Software {
    type Decoder = SoftwareDecoder;
    type Encoder = SoftwareEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`Software`] decoder.
#[derive(Debug, Default)]
pub struct SoftwareDecoder(Utf8Decoder);
impl SoftwareDecoder {
    /// Makes a new `SoftwareDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(SoftwareDecoder, Software, Software::new);

/// [`Software`] encoder.
#[derive(Debug, Default)]
pub struct SoftwareEncoder(Utf8Encoder<Cow<'static, str>>);
impl SoftwareEncoder {
    /// Makes a new `SoftwareEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(SoftwareEncoder, Software, |item: Self::Item| item
    .description);

/// `UNKNOWN-ATTRIBUTES` attribute.
///
/// See [RFC 5389 -- 15.9. UNKNOWN-ATTRIBUTES] about this attribute.
///
/// [RFC 5389 -- 15.9. UNKNOWN-ATTRIBUTES]: https://tools.ietf.org/html/rfc5389#section-15.9
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownAttributes {
    unknowns: Vec<AttributeType>,
}
impl UnknownAttributes {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x000A;

    /// Makes a new `UnknownAttributes` instance.
    pub fn new(unknowns: Vec<AttributeType>) -> Self {
        UnknownAttributes { unknowns }
    }

    /// Returns the unknown attribute types of this instance.
    pub fn unknowns(&self) -> &[AttributeType] {
        &self.unknowns
    }
}
impl Attribute for UnknownAttributes {
    type Decoder = UnknownAttributesDecoder;
    type Encoder = UnknownAttributesEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`UnknownAttributes`] decoder.
#[derive(Debug, Default)]
pub struct UnknownAttributesDecoder(Collect<U16beDecoder, Vec<u16>>);
impl UnknownAttributesDecoder {
    /// Makes a new `UnknownAttributesDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(UnknownAttributesDecoder, UnknownAttributes, |vs: Vec<
    u16,
>| Ok(
    UnknownAttributes {
        unknowns: vs.into_iter().map(AttributeType::new).collect()
    }
));

/// [`UnknownAttributes`] encoder.
#[derive(Debug, Default)]
pub struct UnknownAttributesEncoder(PreEncode<Repeat<U16beEncoder, vec::IntoIter<u16>>>);
impl UnknownAttributesEncoder {
    /// Makes a new `UnknownAttributesEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
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
/// See [RFC 5389 -- 15.3. USERNAME] about this attribute.
///
/// [RFC 5389 -- 15.3. USERNAME]: https://tools.ietf.org/html/rfc5389#section-15.3
///
/// # TODO
///
/// - Support SASLprep [RFC 4013]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Username {
    name: String,
}
impl Username {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0006;

    /// Makes a new `Username` instance.
    ///
    /// # Errors
    ///
    /// The length of `name` must be less then `513` bytes.
    /// If it is too long, this will return an `ErrorKind::InvalidInput` error.
    pub fn new(name: String) -> Result<Self> {
        track_assert!(name.len() < 513, ErrorKind::InvalidInput; name);
        Ok(Username { name })
    }

    /// Returns the name of this instance.
    pub fn name(&self) -> &str {
        &self.name
    }
}
impl Attribute for Username {
    type Decoder = UsernameDecoder;
    type Encoder = UsernameEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`Username`] decoder.
#[derive(Debug, Default)]
pub struct UsernameDecoder(Utf8Decoder);
impl UsernameDecoder {
    /// Makes a new `UsernameDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(UsernameDecoder, Username, Username::new);

/// [`Username`] encoder.
#[derive(Debug, Default)]
pub struct UsernameEncoder(Utf8Encoder);
impl UsernameEncoder {
    /// Makes a new `UsernameEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(UsernameEncoder, Username, |item: Self::Item| item.name);

/// `XOR-MAPPED-ADDRESS` attribute.
///
/// See [RFC 5389 -- 15.2. XOR-MAPPED-ADDRESS] about this attribute.
///
/// [RFC 5389 -- 15.2. XOR-MAPPED-ADDRESS]: https://tools.ietf.org/html/rfc5389#section-15.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XorMappedAddress(SocketAddr);
impl XorMappedAddress {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0020;

    /// Makes a new `XorMappedAddress` instance.
    pub fn new(addr: SocketAddr) -> Self {
        XorMappedAddress(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl Attribute for XorMappedAddress {
    type Decoder = XorMappedAddressDecoder;
    type Encoder = XorMappedAddressEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }

    fn before_encode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        self.0 = socket_addr_xor(self.0, message.transaction_id());
        Ok(())
    }

    fn after_decode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        self.0 = socket_addr_xor(self.0, message.transaction_id());
        Ok(())
    }
}

/// [`XorMappedAddress`] decoder.
#[derive(Debug, Default)]
pub struct XorMappedAddressDecoder(SocketAddrDecoder);
impl XorMappedAddressDecoder {
    /// Makes a new `XorMappedAddressDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(XorMappedAddressDecoder, XorMappedAddress, |item| Ok(
    XorMappedAddress(item)
));

/// [`XorMappedAddress`] encoder.
#[derive(Debug, Default)]
pub struct XorMappedAddressEncoder(SocketAddrEncoder);
impl XorMappedAddressEncoder {
    /// Makes a new `XorMappedAddressEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    XorMappedAddressEncoder,
    XorMappedAddress,
    |item: Self::Item| item.0
);

/// `XOR-MAPPED-ADDRESS` attribute with an alternative code.
///
/// Such attribute is returned by e.g. "Vovida.org 0.98-CPC" on stun.counterpath.net
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XorMappedAddress2(SocketAddr);
impl XorMappedAddress2 {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x8020;

    /// Makes a new `XorMappedAddress2` instance.
    pub fn new(addr: SocketAddr) -> Self {
        XorMappedAddress2(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl Attribute for XorMappedAddress2 {
    type Decoder = XorMappedAddress2Decoder;
    type Encoder = XorMappedAddress2Encoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }

    fn before_encode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        self.0 = socket_addr_xor(self.0, message.transaction_id());
        Ok(())
    }

    fn after_decode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        self.0 = socket_addr_xor(self.0, message.transaction_id());
        Ok(())
    }
}

/// [`XorMappedAddress2`] decoder.
#[derive(Debug, Default)]
pub struct XorMappedAddress2Decoder(SocketAddrDecoder);
impl XorMappedAddress2Decoder {
    /// Makes a new `XorMappedAddressDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(XorMappedAddress2Decoder, XorMappedAddress2, |item| Ok(
    XorMappedAddress2(item)
));

/// [`XorMappedAddress`] encoder.
#[derive(Debug, Default)]
pub struct XorMappedAddress2Encoder(SocketAddrEncoder);
impl XorMappedAddress2Encoder {
    /// Makes a new `XorMappedAddressEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    XorMappedAddress2Encoder,
    XorMappedAddress2,
    |item: Self::Item| item.0
);
