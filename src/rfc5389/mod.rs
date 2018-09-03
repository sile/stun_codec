//! [RFC 5389] specific components.
//!
//! [RFC 5389]: https://tools.ietf.org/html/rfc5389
use bytecodec::{
    ByteCount, Decode, Encode, EncodeExt, Eos, ErrorKind, Result, SizedEncode, TryTaggedDecode,
};

use num::U12;
use {AttributeType, Message};

pub mod attributes;
pub mod errors;
pub mod methods;

/// Method set that are defined in [RFC 5389].
///
/// [RFC 5389]: https://tools.ietf.org/html/rfc5389
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// See [Binding].
    ///
    /// [Binding]: ./methods/struct.Binding.html
    Binding,
}
impl ::Method for Method {
    fn from_u12(value: U12) -> Option<Self> {
        match value.as_u16() {
            methods::Binding::CODEPOINT => Some(Method::Binding),
            _ => None,
        }
    }

    fn as_u12(&self) -> U12 {
        match *self {
            Method::Binding => methods::Binding.as_u12(),
        }
    }
}
impl From<methods::Binding> for Method {
    fn from(_: methods::Binding) -> Self {
        Method::Binding
    }
}

macro_rules! impl_from {
    ($to:ident, $variant:ident, $from:ident) => {
        impl From<attributes::$from> for $to {
            fn from(f: attributes::$from) -> Self {
                $to::$variant(f)
            }
        }
    };
}

/// Attribute set that are defined in [RFC 5389].
///
/// [RFC 5389]: https://tools.ietf.org/html/rfc5389
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Attribute {
    MappedAddress(attributes::MappedAddress),
    Username(attributes::Username),
    MessageIntegrity(attributes::MessageIntegrity),
    ErrorCode(attributes::ErrorCode),
    UnknownAttributes(attributes::UnknownAttributes),
    Realm(attributes::Realm),
    Nonce(attributes::Nonce),
    XorMappedAddress(attributes::XorMappedAddress),
    Software(attributes::Software),
    AlternateServer(attributes::AlternateServer),
    Fingerprint(attributes::Fingerprint),
}
impl_from!(Attribute, MappedAddress, MappedAddress);
impl_from!(Attribute, Username, Username);
impl_from!(Attribute, MessageIntegrity, MessageIntegrity);
impl_from!(Attribute, ErrorCode, ErrorCode);
impl_from!(Attribute, UnknownAttributes, UnknownAttributes);
impl_from!(Attribute, Realm, Realm);
impl_from!(Attribute, Nonce, Nonce);
impl_from!(Attribute, XorMappedAddress, XorMappedAddress);
impl_from!(Attribute, Software, Software);
impl_from!(Attribute, AlternateServer, AlternateServer);
impl_from!(Attribute, Fingerprint, Fingerprint);
impl ::Attribute for Attribute {
    type Decoder = AttributeDecoder;
    type Encoder = AttributeEncoder;

    fn get_type(&self) -> AttributeType {
        match self {
            Attribute::MappedAddress(a) => a.get_type(),
            Attribute::Username(a) => a.get_type(),
            Attribute::MessageIntegrity(a) => a.get_type(),
            Attribute::ErrorCode(a) => a.get_type(),
            Attribute::UnknownAttributes(a) => a.get_type(),
            Attribute::Realm(a) => a.get_type(),
            Attribute::Nonce(a) => a.get_type(),
            Attribute::XorMappedAddress(a) => a.get_type(),
            Attribute::Software(a) => a.get_type(),
            Attribute::AlternateServer(a) => a.get_type(),
            Attribute::Fingerprint(a) => a.get_type(),
        }
    }

    fn before_encode<M, A>(&mut self, message: &Message<M, A>) -> Result<()>
    where
        M: ::Method,
        A: ::Attribute,
    {
        match self {
            Attribute::MappedAddress(a) => track!(a.before_encode(message)),
            Attribute::Username(a) => track!(a.before_encode(message)),
            Attribute::MessageIntegrity(a) => track!(a.before_encode(message)),
            Attribute::ErrorCode(a) => track!(a.before_encode(message)),
            Attribute::UnknownAttributes(a) => track!(a.before_encode(message)),
            Attribute::Realm(a) => track!(a.before_encode(message)),
            Attribute::Nonce(a) => track!(a.before_encode(message)),
            Attribute::XorMappedAddress(a) => track!(a.before_encode(message)),
            Attribute::Software(a) => track!(a.before_encode(message)),
            Attribute::AlternateServer(a) => track!(a.before_encode(message)),
            Attribute::Fingerprint(a) => track!(a.before_encode(message)),
        }
    }

    fn after_decode<M, A>(&mut self, message: &Message<M, A>) -> Result<()>
    where
        M: ::Method,
        A: ::Attribute,
    {
        match self {
            Attribute::MappedAddress(a) => track!(a.after_decode(message)),
            Attribute::Username(a) => track!(a.after_decode(message)),
            Attribute::MessageIntegrity(a) => track!(a.after_decode(message)),
            Attribute::ErrorCode(a) => track!(a.after_decode(message)),
            Attribute::UnknownAttributes(a) => track!(a.after_decode(message)),
            Attribute::Realm(a) => track!(a.after_decode(message)),
            Attribute::Nonce(a) => track!(a.after_decode(message)),
            Attribute::XorMappedAddress(a) => track!(a.after_decode(message)),
            Attribute::Software(a) => track!(a.after_decode(message)),
            Attribute::AlternateServer(a) => track!(a.after_decode(message)),
            Attribute::Fingerprint(a) => track!(a.after_decode(message)),
        }
    }
}

/// [`Attribute`] decoder.
///
/// [`Attribute`]: ./enum.Attribute.html
#[derive(Debug, Default)]
pub struct AttributeDecoder(AttributeDecoderInner);
impl AttributeDecoder {
    /// Makes a new `AttributeDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl Decode for AttributeDecoder {
    type Item = Attribute;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        self.0.decode(buf, eos)
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        self.0.finish_decoding()
    }

    fn requiring_bytes(&self) -> ByteCount {
        self.0.requiring_bytes()
    }

    fn is_idle(&self) -> bool {
        self.0.is_idle()
    }
}
impl TryTaggedDecode for AttributeDecoder {
    type Tag = AttributeType;

    fn try_start_decoding(&mut self, tag: Self::Tag) -> Result<bool> {
        self.0.try_start_decoding(tag)
    }
}

#[derive(Debug)]
enum AttributeDecoderInner {
    MappedAddress(attributes::MappedAddressDecoder),
    Username(attributes::UsernameDecoder),
    MessageIntegrity(attributes::MessageIntegrityDecoder),
    ErrorCode(attributes::ErrorCodeDecoder),
    UnknownAttributes(attributes::UnknownAttributesDecoder),
    Realm(attributes::RealmDecoder),
    Nonce(attributes::NonceDecoder),
    XorMappedAddress(attributes::XorMappedAddressDecoder),
    Software(attributes::SoftwareDecoder),
    AlternateServer(attributes::AlternateServerDecoder),
    Fingerprint(attributes::FingerprintDecoder),
    None,
}
impl Default for AttributeDecoderInner {
    fn default() -> Self {
        AttributeDecoderInner::None
    }
}
impl Decode for AttributeDecoderInner {
    type Item = Attribute;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        match self {
            AttributeDecoderInner::MappedAddress(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::Username(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::MessageIntegrity(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::ErrorCode(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::UnknownAttributes(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::Realm(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::Nonce(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::XorMappedAddress(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::Software(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::AlternateServer(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::Fingerprint(a) => track!(a.decode(buf, eos)),
            AttributeDecoderInner::None => track_panic!(ErrorKind::InconsistentState),
        }
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let item = match self {
            AttributeDecoderInner::MappedAddress(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::Username(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::MessageIntegrity(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::ErrorCode(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::UnknownAttributes(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::Realm(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::Nonce(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::XorMappedAddress(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::Software(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::AlternateServer(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::Fingerprint(a) => track!(a.finish_decoding())?.into(),
            AttributeDecoderInner::None => track_panic!(ErrorKind::IncompleteDecoding),
        };
        *self = AttributeDecoderInner::None;
        Ok(item)
    }

    fn requiring_bytes(&self) -> ByteCount {
        match self {
            AttributeDecoderInner::MappedAddress(a) => a.requiring_bytes(),
            AttributeDecoderInner::Username(a) => a.requiring_bytes(),
            AttributeDecoderInner::MessageIntegrity(a) => a.requiring_bytes(),
            AttributeDecoderInner::ErrorCode(a) => a.requiring_bytes(),
            AttributeDecoderInner::UnknownAttributes(a) => a.requiring_bytes(),
            AttributeDecoderInner::Realm(a) => a.requiring_bytes(),
            AttributeDecoderInner::Nonce(a) => a.requiring_bytes(),
            AttributeDecoderInner::XorMappedAddress(a) => a.requiring_bytes(),
            AttributeDecoderInner::Software(a) => a.requiring_bytes(),
            AttributeDecoderInner::AlternateServer(a) => a.requiring_bytes(),
            AttributeDecoderInner::Fingerprint(a) => a.requiring_bytes(),
            AttributeDecoderInner::None => ByteCount::Finite(0),
        }
    }

    fn is_idle(&self) -> bool {
        match self {
            AttributeDecoderInner::MappedAddress(a) => a.is_idle(),
            AttributeDecoderInner::Username(a) => a.is_idle(),
            AttributeDecoderInner::MessageIntegrity(a) => a.is_idle(),
            AttributeDecoderInner::ErrorCode(a) => a.is_idle(),
            AttributeDecoderInner::UnknownAttributes(a) => a.is_idle(),
            AttributeDecoderInner::Realm(a) => a.is_idle(),
            AttributeDecoderInner::Nonce(a) => a.is_idle(),
            AttributeDecoderInner::XorMappedAddress(a) => a.is_idle(),
            AttributeDecoderInner::Software(a) => a.is_idle(),
            AttributeDecoderInner::AlternateServer(a) => a.is_idle(),
            AttributeDecoderInner::Fingerprint(a) => a.is_idle(),
            AttributeDecoderInner::None => true,
        }
    }
}
impl TryTaggedDecode for AttributeDecoderInner {
    type Tag = AttributeType;

    fn try_start_decoding(&mut self, tag: Self::Tag) -> Result<bool> {
        *self = match tag.as_u16() {
            attributes::MappedAddress::CODEPOINT => attributes::MappedAddressDecoder::new().into(),
            attributes::Username::CODEPOINT => attributes::UsernameDecoder::new().into(),
            attributes::MessageIntegrity::CODEPOINT => {
                attributes::MessageIntegrityDecoder::new().into()
            }
            attributes::ErrorCode::CODEPOINT => attributes::ErrorCodeDecoder::new().into(),
            attributes::UnknownAttributes::CODEPOINT => {
                attributes::UnknownAttributesDecoder::new().into()
            }
            attributes::Realm::CODEPOINT => attributes::RealmDecoder::new().into(),
            attributes::Nonce::CODEPOINT => attributes::NonceDecoder::new().into(),
            attributes::XorMappedAddress::CODEPOINT => {
                attributes::XorMappedAddressDecoder::new().into()
            }
            attributes::Software::CODEPOINT => attributes::SoftwareDecoder::new().into(),
            attributes::AlternateServer::CODEPOINT => {
                attributes::AlternateServerDecoder::new().into()
            }
            attributes::Fingerprint::CODEPOINT => attributes::FingerprintDecoder::new().into(),
            _ => return Ok(false),
        };
        Ok(true)
    }
}
impl_from!(AttributeDecoderInner, MappedAddress, MappedAddressDecoder);
impl_from!(AttributeDecoderInner, Username, UsernameDecoder);
impl_from!(
    AttributeDecoderInner,
    MessageIntegrity,
    MessageIntegrityDecoder
);
impl_from!(AttributeDecoderInner, ErrorCode, ErrorCodeDecoder);
impl_from!(
    AttributeDecoderInner,
    UnknownAttributes,
    UnknownAttributesDecoder
);
impl_from!(AttributeDecoderInner, Realm, RealmDecoder);
impl_from!(AttributeDecoderInner, Nonce, NonceDecoder);
impl_from!(
    AttributeDecoderInner,
    XorMappedAddress,
    XorMappedAddressDecoder
);
impl_from!(AttributeDecoderInner, Software, SoftwareDecoder);
impl_from!(
    AttributeDecoderInner,
    AlternateServer,
    AlternateServerDecoder
);
impl_from!(AttributeDecoderInner, Fingerprint, FingerprintDecoder);

/// [`Attribute`] encoder.
///
/// [`Attribute`]: ./enum.Attribute.html
#[derive(Debug, Default)]
pub struct AttributeEncoder(AttributeEncoderInner);
impl AttributeEncoder {
    /// Makes a new `AttributeEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl Encode for AttributeEncoder {
    type Item = Attribute;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        self.0.encode(buf, eos)
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        self.0.start_encoding(item)
    }

    fn requiring_bytes(&self) -> ByteCount {
        self.0.requiring_bytes()
    }

    fn is_idle(&self) -> bool {
        self.0.is_idle()
    }
}
impl SizedEncode for AttributeEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.0.exact_requiring_bytes()
    }
}

#[derive(Debug)]
enum AttributeEncoderInner {
    MappedAddress(attributes::MappedAddressEncoder),
    Username(attributes::UsernameEncoder),
    MessageIntegrity(attributes::MessageIntegrityEncoder),
    ErrorCode(attributes::ErrorCodeEncoder),
    UnknownAttributes(attributes::UnknownAttributesEncoder),
    Realm(attributes::RealmEncoder),
    Nonce(attributes::NonceEncoder),
    XorMappedAddress(attributes::XorMappedAddressEncoder),
    Software(attributes::SoftwareEncoder),
    AlternateServer(attributes::AlternateServerEncoder),
    Fingerprint(attributes::FingerprintEncoder),
    None,
}
impl Default for AttributeEncoderInner {
    fn default() -> Self {
        AttributeEncoderInner::None
    }
}
impl Encode for AttributeEncoderInner {
    type Item = Attribute;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        match self {
            AttributeEncoderInner::MappedAddress(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::Username(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::MessageIntegrity(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::ErrorCode(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::UnknownAttributes(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::Realm(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::Nonce(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::XorMappedAddress(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::Software(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::AlternateServer(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::Fingerprint(a) => track!(a.encode(buf, eos)),
            AttributeEncoderInner::None => Ok(0),
        }
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        track_assert!(self.is_idle(), ErrorKind::EncoderFull; item);
        *self = match item {
            Attribute::MappedAddress(a) => {
                track!(attributes::MappedAddressEncoder::with_item(a))?.into()
            }
            Attribute::Username(a) => track!(attributes::UsernameEncoder::with_item(a))?.into(),
            Attribute::MessageIntegrity(a) => {
                track!(attributes::MessageIntegrityEncoder::with_item(a))?.into()
            }
            Attribute::ErrorCode(a) => track!(attributes::ErrorCodeEncoder::with_item(a))?.into(),
            Attribute::UnknownAttributes(a) => {
                track!(attributes::UnknownAttributesEncoder::with_item(a))?.into()
            }
            Attribute::Realm(a) => track!(attributes::RealmEncoder::with_item(a))?.into(),
            Attribute::Nonce(a) => track!(attributes::NonceEncoder::with_item(a))?.into(),
            Attribute::XorMappedAddress(a) => {
                track!(attributes::XorMappedAddressEncoder::with_item(a))?.into()
            }
            Attribute::Software(a) => track!(attributes::SoftwareEncoder::with_item(a))?.into(),
            Attribute::AlternateServer(a) => {
                track!(attributes::AlternateServerEncoder::with_item(a))?.into()
            }
            Attribute::Fingerprint(a) => {
                track!(attributes::FingerprintEncoder::with_item(a))?.into()
            }
        };
        Ok(())
    }

    fn requiring_bytes(&self) -> ByteCount {
        ByteCount::Finite(self.exact_requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        match self {
            AttributeEncoderInner::MappedAddress(a) => a.is_idle(),
            AttributeEncoderInner::Username(a) => a.is_idle(),
            AttributeEncoderInner::MessageIntegrity(a) => a.is_idle(),
            AttributeEncoderInner::ErrorCode(a) => a.is_idle(),
            AttributeEncoderInner::UnknownAttributes(a) => a.is_idle(),
            AttributeEncoderInner::Realm(a) => a.is_idle(),
            AttributeEncoderInner::Nonce(a) => a.is_idle(),
            AttributeEncoderInner::XorMappedAddress(a) => a.is_idle(),
            AttributeEncoderInner::Software(a) => a.is_idle(),
            AttributeEncoderInner::AlternateServer(a) => a.is_idle(),
            AttributeEncoderInner::Fingerprint(a) => a.is_idle(),
            AttributeEncoderInner::None => true,
        }
    }
}
impl SizedEncode for AttributeEncoderInner {
    fn exact_requiring_bytes(&self) -> u64 {
        match self {
            AttributeEncoderInner::MappedAddress(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::Username(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::MessageIntegrity(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::ErrorCode(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::UnknownAttributes(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::Realm(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::Nonce(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::XorMappedAddress(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::Software(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::AlternateServer(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::Fingerprint(a) => a.exact_requiring_bytes(),
            AttributeEncoderInner::None => 0,
        }
    }
}
impl_from!(AttributeEncoderInner, MappedAddress, MappedAddressEncoder);
impl_from!(AttributeEncoderInner, Username, UsernameEncoder);
impl_from!(
    AttributeEncoderInner,
    MessageIntegrity,
    MessageIntegrityEncoder
);
impl_from!(AttributeEncoderInner, ErrorCode, ErrorCodeEncoder);
impl_from!(
    AttributeEncoderInner,
    UnknownAttributes,
    UnknownAttributesEncoder
);
impl_from!(AttributeEncoderInner, Realm, RealmEncoder);
impl_from!(AttributeEncoderInner, Nonce, NonceEncoder);
impl_from!(
    AttributeEncoderInner,
    XorMappedAddress,
    XorMappedAddressEncoder
);
impl_from!(AttributeEncoderInner, Software, SoftwareEncoder);
impl_from!(
    AttributeEncoderInner,
    AlternateServer,
    AlternateServerEncoder
);
impl_from!(AttributeEncoderInner, Fingerprint, FingerprintEncoder);
