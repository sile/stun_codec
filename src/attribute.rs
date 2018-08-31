use bytecodec::bytes::{BytesDecoder, BytesEncoder};
use bytecodec::combinator::{Length, Peekable};
use bytecodec::fixnum::{U16beDecoder, U16beEncoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, Result, SizedEncode, TaggedDecode};

use message::{Message, Method};

#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct AttrType(u16);
impl AttrType {
    pub fn new(codepoint: u16) -> Self {
        AttrType(codepoint)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn is_comprehension_required(&self) -> bool {
        self.0 < 0x8000
    }

    pub fn is_comprehension_optional(&self) -> bool {
        !self.is_comprehension_required()
    }
}
impl From<u16> for AttrType {
    fn from(f: u16) -> Self {
        Self::new(f)
    }
}

// PaddedAttribute(?)
#[derive(Debug, Clone)]
pub struct Attr<T> {
    value: T,
    padding: Option<Padding>,
}
impl<T: AttrValue> Attr<T> {
    pub fn new(value: T) -> Self {
        Attr {
            value,
            padding: None,
        }
    }

    pub fn attr_type(&self) -> AttrType {
        self.value.attr_type()
    }

    pub fn value(&self) -> &T {
        &self.value
    }
}

#[derive(Debug, Default)]
pub struct AttrDecoder<T: AttrValue> {
    attr_type: U16beDecoder,
    value_len: Peekable<U16beDecoder>,
    value: Length<T::Decoder>,
    padding: BytesDecoder<Padding>,
}
impl<T: AttrValue> Decode for AttrDecoder<T> {
    type Item = Attr<T>;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        if !self.value_len.is_idle() {
            bytecodec_try_decode!(self.attr_type, offset, buf, eos);
            bytecodec_try_decode!(self.value_len, offset, buf, eos);

            let attr_type = AttrType(track!(self.attr_type.finish_decoding())?);
            track!(self.value.inner_mut().start_decoding(attr_type))?;

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
        Ok(Attr {
            value,
            padding: Some(padding),
        })
    }

    fn requiring_bytes(&self) -> ByteCount {
        if self.value_len.is_idle() {
            self.value
                .requiring_bytes()
                .add_for_decoding(self.padding.requiring_bytes())
        } else {
            self.attr_type
                .requiring_bytes()
                .add_for_decoding(self.value_len.requiring_bytes())
        }
    }

    fn is_idle(&self) -> bool {
        self.attr_type.is_idle()
            && self.value_len.is_idle()
            && self.value.is_idle()
            && self.padding.is_idle()
    }
}

#[derive(Debug)]
pub struct AttrEncoder<T: AttrValue> {
    attr_type: U16beEncoder,
    value_len: U16beEncoder,
    value: T::Encoder,
    padding: BytesEncoder<Padding>,
}
impl<T: AttrValue> Default for AttrEncoder<T> {
    fn default() -> Self {
        AttrEncoder {
            attr_type: Default::default(),
            value_len: Default::default(),
            value: Default::default(),
            padding: Default::default(),
        }
    }
}
impl<T: AttrValue> Encode for AttrEncoder<T> {
    type Item = Attr<T>;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        bytecodec_try_encode!(self.attr_type, offset, buf, eos);
        bytecodec_try_encode!(self.value_len, offset, buf, eos);
        bytecodec_try_encode!(self.value, offset, buf, eos);
        bytecodec_try_encode!(self.padding, offset, buf, eos);
        Ok(offset)
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        track!(self.attr_type.start_encoding(item.attr_type().as_u16()))?;
        track!(self.value.start_encoding(item.value))?;

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
        self.attr_type.is_idle()
            && self.value_len.is_idle()
            && self.value.is_idle()
            && self.padding.is_idle()
    }
}
impl<T: AttrValue> SizedEncode for AttrEncoder<T> {
    fn exact_requiring_bytes(&self) -> u64 {
        self.attr_type.exact_requiring_bytes()
            + self.value_len.exact_requiring_bytes()
            + self.value.exact_requiring_bytes()
            + self.padding.exact_requiring_bytes()
    }
}

pub trait AttrValue: Sized + Clone {
    type Decoder: TaggedDecode<Tag = AttrType, Item = Self> + Default;
    type Encoder: SizedEncode<Item = Self> + Default;

    fn attr_type(&self) -> AttrType;

    #[allow(unused_variables)]
    fn before_encode<M: Method, A: AttrValue>(&mut self, message: &Message<M, A>) -> Result<()> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn after_decode<M: Method, A: AttrValue>(&mut self, message: &Message<M, A>) -> Result<()> {
        Ok(())
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
