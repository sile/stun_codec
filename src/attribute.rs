use bytecodec::bytes::{BytesDecoder, BytesEncoder};
use bytecodec::combinator::{Length, Peekable};
use bytecodec::fixnum::{U16beDecoder, U16beEncoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, Result, SizedEncode, TaggedDecode};

use message::Message;
use Method;

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
/// > [RFC 5389 -- 5. Definitions](https://tools.ietf.org/html/rfc5389#section-5)
pub trait Attribute: Sized + Clone {
    /// The decoder of the value part of the attribute.
    type Decoder: Default + TaggedDecode<Tag = AttributeType, Item = Self>;

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
    fn before_encode<M: Method, A: Attribute>(&mut self, message: &Message<M, A>) -> Result<()> {
        Ok(())
    }

    /// This method is called after decoding the attribute and before being appended to the given message.
    ///
    /// The default implementation simply returns `Ok(())`.
    #[allow(unused_variables)]
    fn after_decode<M: Method, A: Attribute>(&mut self, message: &Message<M, A>) -> Result<()> {
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
/// > [RFC 5389 -- 5. Definitions](https://tools.ietf.org/html/rfc5389#section-5)
/// >
/// > ---
/// >
/// > A STUN Attribute type is a hex number in the range 0x0000 - 0xFFFF.
/// > STUN attribute types in the range 0x0000 - 0x7FFF are considered
/// > comprehension-required; STUN attribute types in the range 0x8000 -
/// > 0xFFFF are considered comprehension-optional.
/// >
/// > [RFC 5389 -- 18.2. STUN Attribute Registry]
/// > (https://tools.ietf.org/html/rfc5389#section-18.2)
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct AttributeType(u16);
impl AttributeType {
    /// Makes a new `Type` instance which corresponding to `codepoint`.
    pub fn new(codepoint: u16) -> Self {
        AttributeType(codepoint)
    }

    /// Returns the attribute codepoint corresponding this instance.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// Returns `true` if this is a comprehension-required type.
    pub fn is_comprehension_required(&self) -> bool {
        self.0 < 0x8000
    }

    /// Returns `true` if this is a comprehension-optional type.
    pub fn is_comprehension_optional(&self) -> bool {
        !self.is_comprehension_required()
    }
}
impl From<u16> for AttributeType {
    fn from(f: u16) -> Self {
        Self::new(f)
    }
}

#[derive(Debug, Clone)]
pub struct LosslessAttribute<T> {
    inner: T,
    padding: Option<Padding>,
}
impl<T: Attribute> LosslessAttribute<T> {
    pub fn new(inner: T) -> Self {
        LosslessAttribute {
            inner,
            padding: None,
        }
    }

    pub fn inner_ref(&self) -> &T {
        &self.inner
    }
}

#[derive(Debug, Default)]
pub struct LosslessAttributeDecoder<T: Attribute> {
    get_type: U16beDecoder,
    value_len: Peekable<U16beDecoder>,
    value: Length<T::Decoder>,
    padding: BytesDecoder<Padding>,
}
impl<T: Attribute> Decode for LosslessAttributeDecoder<T> {
    type Item = LosslessAttribute<T>;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        if !self.value_len.is_idle() {
            bytecodec_try_decode!(self.get_type, offset, buf, eos);
            bytecodec_try_decode!(self.value_len, offset, buf, eos);

            let get_type = AttributeType(track!(self.get_type.finish_decoding())?);
            track!(self.value.inner_mut().start_decoding(get_type))?;

            let value_len = *self.value_len.peek().expect("never fails");
            track!(self.value.set_expected_bytes(u64::from(value_len)))?;
            self.padding.set_bytes(Padding::new(value_len as usize));
        }
        bytecodec_try_decode!(self.value, offset, buf, eos);
        bytecodec_try_decode!(self.padding, offset, buf, eos);
        Ok(offset)
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let _ = track!(self.value_len.finish_decoding())?;
        let value = track!(self.value.finish_decoding())?;
        let padding = track!(self.padding.finish_decoding())?;
        Ok(LosslessAttribute {
            inner: value,
            padding: Some(padding),
        })
    }

    fn requiring_bytes(&self) -> ByteCount {
        if self.value_len.is_idle() {
            self.value
                .requiring_bytes()
                .add_for_decoding(self.padding.requiring_bytes())
        } else {
            self.get_type
                .requiring_bytes()
                .add_for_decoding(self.value_len.requiring_bytes())
        }
    }

    fn is_idle(&self) -> bool {
        self.get_type.is_idle()
            && self.value_len.is_idle()
            && self.value.is_idle()
            && self.padding.is_idle()
    }
}

#[derive(Debug)]
pub struct LosslessAttributeEncoder<T: Attribute> {
    get_type: U16beEncoder,
    value_len: U16beEncoder,
    value: T::Encoder,
    padding: BytesEncoder<Padding>,
}
impl<T: Attribute> Default for LosslessAttributeEncoder<T> {
    fn default() -> Self {
        LosslessAttributeEncoder {
            get_type: Default::default(),
            value_len: Default::default(),
            value: Default::default(),
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
        bytecodec_try_encode!(self.value, offset, buf, eos);
        bytecodec_try_encode!(self.padding, offset, buf, eos);
        Ok(offset)
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        track!(
            self.get_type
                .start_encoding(item.inner_ref().get_type().as_u16())
        )?;
        track!(self.value.start_encoding(item.inner))?;

        let value_len = self.value.exact_requiring_bytes() as u16;
        let padding = Padding::new(value_len as usize);
        track!(self.value_len.start_encoding(value_len))?;
        track!(self.padding.start_encoding(padding))?;
        Ok(())
    }

    fn requiring_bytes(&self) -> ByteCount {
        ByteCount::Finite(self.exact_requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.get_type.is_idle()
            && self.value_len.is_idle()
            && self.value.is_idle()
            && self.padding.is_idle()
    }
}
impl<T: Attribute> SizedEncode for LosslessAttributeEncoder<T> {
    fn exact_requiring_bytes(&self) -> u64 {
        self.get_type.exact_requiring_bytes()
            + self.value_len.exact_requiring_bytes()
            + self.value.exact_requiring_bytes()
            + self.padding.exact_requiring_bytes()
    }
}

#[derive(Debug, Default, Clone)]
struct Padding {
    buf: [u8; 4],
    len: usize,
}
impl Padding {
    fn new(value_len: usize) -> Self {
        let len = (4 - value_len % 4) % 4;
        Padding { buf: [0; 4], len }
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
