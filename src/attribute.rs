use bytecodec::bytes::{BytesDecoder, BytesEncoder, RemainingBytesDecoder};
use bytecodec::combinator::{Length, Peekable};
use bytecodec::fixnum::{U16beDecoder, U16beEncoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, ErrorKind, Result, SizedEncode, TryTaggedDecode};
use std::fmt;

use message::Message;

/// STUN attribute.
///
/// > **Attribute**:  The STUN term for a Type-Length-Value (TLV) object that
/// > can be added to a STUN message. Attributes are divided into two
/// > types: comprehension-required and comprehension-optional. STUN
/// > agents can safely ignore comprehension-optional attributes they
/// > don't understand, but cannot successfully process a message if it
/// > contains comprehension-required attributes that are not
/// > understood.
/// >
/// > [RFC 5389 -- 5. Definitions]
///
/// [RFC 5389 -- 5. Definitions]: https://tools.ietf.org/html/rfc5389#section-5
pub trait Attribute: Sized + Clone {
    /// The decoder of the value part of the attribute.
    type Decoder: Default + TryTaggedDecode<Tag = AttributeType, Item = Self>;

    /// The encoder of the value part of the attribute.
    type Encoder: Default + SizedEncode<Item = Self>;

    /// Returns the type of the attribute.
    fn get_type(&self) -> AttributeType;

    /// This method is called before encoding the attribute.
    ///
    /// `message` is the message to which the attribute belongs.
    /// The message only contains the attributes preceding to `self`.
    ///
    /// The default implementation simply returns `Ok(())`.
    #[allow(unused_variables)]
    fn before_encode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        Ok(())
    }

    /// This method is called after decoding the attribute and before being appended to the given message.
    ///
    /// The default implementation simply returns `Ok(())`.
    #[allow(unused_variables)]
    fn after_decode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        Ok(())
    }
}

/// Attribute type.
///
/// > Attributes are divided into two
/// > types: comprehension-required and comprehension-optional. STUN
/// > agents can safely ignore comprehension-optional attributes they
/// > don't understand, but cannot successfully process a message if it
/// > contains comprehension-required attributes that are not
/// > understood.
/// >
/// > [RFC 5389 -- 5. Definitions]
/// >
/// > ---
/// >
/// > A STUN Attribute type is a hex number in the range 0x0000 - 0xFFFF.
/// > STUN attribute types in the range 0x0000 - 0x7FFF are considered
/// > comprehension-required; STUN attribute types in the range 0x8000 -
/// > 0xFFFF are considered comprehension-optional.
/// >
/// > [RFC 5389 -- 18.2. STUN Attribute Registry]
///
/// [RFC 5389 -- 5. Definitions]: https://tools.ietf.org/html/rfc5389#section-5
/// [RFC 5389 -- 18.2. STUN Attribute Registry]: https://tools.ietf.org/html/rfc5389#section-18.2
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct AttributeType(u16);
impl AttributeType {
    /// Makes a new `Type` instance which corresponding to `codepoint`.
    pub fn new(codepoint: u16) -> Self {
        AttributeType(codepoint)
    }

    /// Returns the attribute codepoint corresponding this instance.
    pub fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns `true` if this is a comprehension-required type.
    pub fn is_comprehension_required(self) -> bool {
        self.0 < 0x8000
    }

    /// Returns `true` if this is a comprehension-optional type.
    pub fn is_comprehension_optional(self) -> bool {
        !self.is_comprehension_required()
    }
}
impl From<u16> for AttributeType {
    fn from(f: u16) -> Self {
        Self::new(f)
    }
}

/// An [`Attribute`] implementation that has raw value bytes.
///
/// [`Attribute`]: ./trait.Attribute.html
#[derive(Debug, Clone)]
pub struct RawAttribute {
    attr_type: AttributeType,
    value: Vec<u8>,
}
impl RawAttribute {
    /// Makes a new `RawAttribute` instance.
    pub fn new(attr_type: AttributeType, value: Vec<u8>) -> Self {
        RawAttribute { attr_type, value }
    }

    /// Returns a reference to the value bytes of the attribute.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Takes ownership of this instance, and returns the value bytes.
    pub fn into_value(self) -> Vec<u8> {
        self.value
    }
}
impl Attribute for RawAttribute {
    type Decoder = RawAttributeDecoder;
    type Encoder = RawAttributeEncoder;

    fn get_type(&self) -> AttributeType {
        self.attr_type
    }
}

/// [`RawAttribute`] decoder.
///
/// [`RawAttribute`]: ./struct.RawAttribute.html
#[derive(Debug, Default)]
pub struct RawAttributeDecoder {
    attr_type: Option<AttributeType>,
    value: RemainingBytesDecoder,
}
impl RawAttributeDecoder {
    /// Makes a new `RawAttributeDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl Decode for RawAttributeDecoder {
    type Item = RawAttribute;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        track!(self.value.decode(buf, eos))
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let attr_type = track_assert_some!(self.attr_type.take(), ErrorKind::InconsistentState);
        let value = track!(self.value.finish_decoding())?;
        Ok(RawAttribute { attr_type, value })
    }

    fn requiring_bytes(&self) -> ByteCount {
        self.value.requiring_bytes()
    }

    fn is_idle(&self) -> bool {
        self.value.is_idle()
    }
}
impl TryTaggedDecode for RawAttributeDecoder {
    type Tag = AttributeType;

    fn try_start_decoding(&mut self, attr_type: Self::Tag) -> Result<bool> {
        self.attr_type = Some(attr_type);
        Ok(true)
    }
}

/// [`RawAttribute`] encoder.
///
/// [`RawAttribute`]: ./struct.RawAttribute.html
#[derive(Debug, Default)]
pub struct RawAttributeEncoder {
    value: BytesEncoder,
}
impl RawAttributeEncoder {
    /// Makes a new `RawAttributeEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl Encode for RawAttributeEncoder {
    type Item = RawAttribute;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        track!(self.value.encode(buf, eos))
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        track!(self.value.start_encoding(item.into_value()))
    }

    fn requiring_bytes(&self) -> ByteCount {
        ByteCount::Finite(self.exact_requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.value.is_idle()
    }
}
impl SizedEncode for RawAttributeEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.value.exact_requiring_bytes()
    }
}

#[derive(Debug, Clone)]
pub enum LosslessAttribute<T> {
    Known {
        inner: T,
        padding: Option<Padding>,
    },
    Unknown {
        inner: RawAttribute,
        padding: Option<Padding>,
    },
}
impl<T: Attribute> LosslessAttribute<T> {
    pub fn new(inner: T) -> Self {
        LosslessAttribute::Known {
            inner,
            padding: None,
        }
    }

    pub fn as_known(&self) -> Option<&T> {
        match self {
            LosslessAttribute::Known { inner, .. } => Some(inner),
            LosslessAttribute::Unknown { .. } => None,
        }
    }

    pub fn as_unknown(&self) -> Option<&RawAttribute> {
        match self {
            LosslessAttribute::Known { .. } => None,
            LosslessAttribute::Unknown { inner, .. } => Some(inner),
        }
    }

    pub fn get_type(&self) -> AttributeType {
        match self {
            LosslessAttribute::Known { inner, .. } => inner.get_type(),
            LosslessAttribute::Unknown { inner, .. } => inner.get_type(),
        }
    }

    pub fn before_encode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        match self {
            LosslessAttribute::Known { inner, .. } => inner.before_encode(message),
            LosslessAttribute::Unknown { inner, .. } => inner.before_encode(message),
        }
    }

    pub fn after_decode<A: Attribute>(&mut self, message: &Message<A>) -> Result<()> {
        match self {
            LosslessAttribute::Known { inner, .. } => inner.after_decode(message),
            LosslessAttribute::Unknown { inner, .. } => inner.after_decode(message),
        }
    }
}

pub struct LosslessAttributeDecoder<T: Attribute> {
    get_type: U16beDecoder,
    value_len: Peekable<U16beDecoder>,
    is_known: bool,
    known_value: Length<T::Decoder>,
    unknown_value: Length<RawAttributeDecoder>,
    padding: BytesDecoder<Padding>,
}
impl<T: Attribute> fmt::Debug for LosslessAttributeDecoder<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LosslessAttributeDecoder {{ .. }}")
    }
}
impl<T: Attribute> Default for LosslessAttributeDecoder<T> {
    fn default() -> Self {
        LosslessAttributeDecoder {
            get_type: Default::default(),
            value_len: Default::default(),
            is_known: false,
            known_value: Default::default(),
            unknown_value: Default::default(),
            padding: Default::default(),
        }
    }
}
impl<T: Attribute> Decode for LosslessAttributeDecoder<T> {
    type Item = LosslessAttribute<T>;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        if !self.value_len.is_idle() {
            bytecodec_try_decode!(self.get_type, offset, buf, eos);
            bytecodec_try_decode!(self.value_len, offset, buf, eos);

            let attr_type = AttributeType(track!(self.get_type.finish_decoding())?);
            let value_len = *self.value_len.peek().expect("never fails");

            self.is_known = track!(self.known_value.inner_mut().try_start_decoding(attr_type))?;
            if self.is_known {
                track!(self.known_value.set_expected_bytes(u64::from(value_len)))?;
            } else {
                track!(self.unknown_value.inner_mut().try_start_decoding(attr_type))?; // must be `true`
                track!(self.unknown_value.set_expected_bytes(u64::from(value_len)))?;
            }
            self.padding.set_bytes(Padding::new(value_len as usize));
        }
        if self.is_known {
            bytecodec_try_decode!(self.known_value, offset, buf, eos);
        } else {
            bytecodec_try_decode!(self.unknown_value, offset, buf, eos);
        }
        bytecodec_try_decode!(self.padding, offset, buf, eos);
        Ok(offset)
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let _ = track!(self.value_len.finish_decoding())?;
        let padding = track!(self.padding.finish_decoding())?;
        if self.is_known {
            let value = track!(self.known_value.finish_decoding())?;
            Ok(LosslessAttribute::Known {
                inner: value,
                padding: Some(padding),
            })
        } else {
            let value = track!(self.unknown_value.finish_decoding())?;
            Ok(LosslessAttribute::Unknown {
                inner: value,
                padding: Some(padding),
            })
        }
    }

    fn requiring_bytes(&self) -> ByteCount {
        if self.value_len.is_idle() {
            if self.is_known {
                self.known_value
                    .requiring_bytes()
                    .add_for_decoding(self.padding.requiring_bytes())
            } else {
                self.unknown_value
                    .requiring_bytes()
                    .add_for_decoding(self.padding.requiring_bytes())
            }
        } else {
            self.get_type
                .requiring_bytes()
                .add_for_decoding(self.value_len.requiring_bytes())
        }
    }

    fn is_idle(&self) -> bool {
        self.value_len.is_idle() && if self.is_known {
            self.known_value.is_idle()
        } else {
            self.unknown_value.is_idle()
        } && self.padding.is_idle()
    }
}

pub struct LosslessAttributeEncoder<T: Attribute> {
    get_type: U16beEncoder,
    value_len: U16beEncoder,
    known_value: T::Encoder,
    unknown_value: RawAttributeEncoder,
    padding: BytesEncoder<Padding>,
}
impl<T: Attribute> fmt::Debug for LosslessAttributeEncoder<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LosslessAttributeEncoder {{ .. }}")
    }
}
impl<T: Attribute> Default for LosslessAttributeEncoder<T> {
    fn default() -> Self {
        LosslessAttributeEncoder {
            get_type: Default::default(),
            value_len: Default::default(),
            known_value: Default::default(),
            unknown_value: Default::default(),
            padding: Default::default(),
        }
    }
}
impl<T: Attribute> Encode for LosslessAttributeEncoder<T> {
    type Item = LosslessAttribute<T>;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        bytecodec_try_encode!(self.get_type, offset, buf, eos);
        bytecodec_try_encode!(self.value_len, offset, buf, eos);
        bytecodec_try_encode!(self.known_value, offset, buf, eos);
        bytecodec_try_encode!(self.unknown_value, offset, buf, eos);
        bytecodec_try_encode!(self.padding, offset, buf, eos);
        Ok(offset)
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        track!(self.get_type.start_encoding(item.get_type().as_u16()))?;
        let padding = match item {
            LosslessAttribute::Known { inner, padding } => {
                track!(self.known_value.start_encoding(inner))?;
                padding
            }
            LosslessAttribute::Unknown { inner, padding } => {
                track!(self.unknown_value.start_encoding(inner))?;
                padding
            }
        };

        let value_len =
            self.known_value.exact_requiring_bytes() + self.unknown_value.exact_requiring_bytes();
        track_assert!(value_len < 0x10000, ErrorKind::InvalidInput; value_len);

        let padding = padding.unwrap_or_else(|| Padding::new(value_len as usize));
        track!(self.value_len.start_encoding(value_len as u16))?;
        track!(self.padding.start_encoding(padding))?;
        Ok(())
    }

    fn requiring_bytes(&self) -> ByteCount {
        ByteCount::Finite(self.exact_requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.value_len.is_idle()
            && self.known_value.is_idle()
            && self.unknown_value.is_idle()
            && self.padding.is_idle()
    }
}
impl<T: Attribute> SizedEncode for LosslessAttributeEncoder<T> {
    fn exact_requiring_bytes(&self) -> u64 {
        self.get_type.exact_requiring_bytes()
            + self.value_len.exact_requiring_bytes()
            + self.known_value.exact_requiring_bytes()
            + self.unknown_value.exact_requiring_bytes()
            + self.padding.exact_requiring_bytes()
    }
}

#[derive(Default, Clone)]
pub struct Padding {
    buf: [u8; 3],
    len: usize,
}
impl Padding {
    fn new(value_len: usize) -> Self {
        let len = (4 - value_len % 4) % 4;
        Padding { buf: [0; 3], len }
    }
}
impl fmt::Debug for Padding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Padding({:?})", self.as_ref())
    }
}
impl AsRef<[u8]> for Padding {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}
impl AsMut<[u8]> for Padding {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}
