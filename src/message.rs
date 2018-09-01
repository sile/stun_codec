use bytecodec::bytes::{BytesDecoder, BytesEncoder};
use bytecodec::combinator::{Collect, Length, Peekable, PreEncode, Repeat};
use bytecodec::fixnum::{U16beDecoder, U16beEncoder, U32beDecoder, U32beEncoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, ErrorKind, Result, SizedEncode};
use std::marker::PhantomData;
use std::vec;

use attribute::{Attr, AttrDecoder, AttrEncoder, AttrValue};
use num::U12;
use TransactionId;

/// The magic cookie value.
///
/// > The magic cookie field **MUST** contain the fixed value `0x2112A442` in
/// > network byte order.
/// > In [RFC 3489](https://tools.ietf.org/html/rfc3489), this field was part of
/// > the transaction ID; placing the magic cookie in this location allows
/// > a server to detect if the client will understand certain attributes
/// > that were added in this revised specification.  In addition, it aids
/// > in distinguishing STUN packets from packets of other protocols when
/// > STUN is multiplexed with those other protocols on the same port.
/// >
/// > ([RFC 5389 -- 6. STUN Message Structure](https://tools.ietf.org/html/rfc5389#section-6))
pub const MAGIC_COOKIE: u32 = 0x2112A442;

pub trait Method: Sized + Clone {
    fn as_u16(&self) -> u16;
    fn as_u12(&self) -> U12;
    fn from_u12(method: U12) -> Result<Self>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}
impl Class {
    /// Returns a `Class` instance which is corresponding to `value`.
    ///
    /// > A class of `0b00` is a request, a class of `0b01` is an
    /// > indication, a class of `0b10` is a success response, and a class of
    /// > `0b11` is an error response.
    /// >
    /// > [RFC 5389 -- 6. STUN Message Structure](https://tools.ietf.org/html/rfc5389#section-6)
    ///
    /// If no such instance exists, this will return `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stun_codec::message::Class;
    ///
    /// assert_eq!(Class::from_u8(0), Some(Class::Request));
    /// assert_eq!(Class::from_u8(9), None);
    /// ```
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0b00 => Some(Class::Request),
            0b01 => Some(Class::Indication),
            0b10 => Some(Class::SuccessResponse),
            0b11 => Some(Class::ErrorResponse),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Message<M, A> {
    class: Class,
    method: M,
    transaction_id: TransactionId,
    attributes: Vec<Attr<A>>,
}
impl<M: Method, A: AttrValue> Message<M, A> {
    pub fn new(class: Class, method: M, transaction_id: TransactionId) -> Self {
        Message {
            class,
            method,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    pub fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }
}

struct MessageHeaderDecoder {
    message_type: U16beDecoder,
    message_len: U16beDecoder,
    magic_cookie: U32beDecoder,
    transaction_id: BytesDecoder<[u8; 12]>,
}
impl Decode for MessageHeaderDecoder {
    type Item = (Type, u16, TransactionId);

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        bytecodec_try_decode!(self.message_type, offset, buf, eos);
        bytecodec_try_decode!(self.message_len, offset, buf, eos);
        bytecodec_try_decode!(self.magic_cookie, offset, buf, eos);
        bytecodec_try_decode!(self.transaction_id, offset, buf, eos);
        Ok(offset)
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let message_type = track!(self.message_type.finish_decoding())?;
        let message_type = track!(Type::from_u16(message_type))?;
        let message_len = track!(self.message_len.finish_decoding())?;
        let magic_cookie = track!(self.magic_cookie.finish_decoding())?;
        let transaction_id = TransactionId::new(track!(self.transaction_id.finish_decoding())?);
        track_assert_eq!(magic_cookie, MAGIC_COOKIE, ErrorKind::InvalidInput);
        Ok((message_type, message_len, transaction_id))
    }

    fn requiring_bytes(&self) -> ByteCount {
        self.message_type
            .requiring_bytes()
            .add_for_decoding(self.message_len.requiring_bytes())
            .add_for_decoding(self.magic_cookie.requiring_bytes())
            .add_for_decoding(self.transaction_id.requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.transaction_id.is_idle()
    }
}

pub struct MessageDecoder<M: Method, A: AttrValue> {
    header: Peekable<MessageHeaderDecoder>,
    attributes: Length<Collect<AttrDecoder<A>, Vec<Attr<A>>>>,
    _phantom: PhantomData<M>,
}
impl<M: Method, A: AttrValue> Decode for MessageDecoder<M, A> {
    type Item = Message<M, A>;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        if !self.header.is_idle() {
            bytecodec_try_decode!(self.header, offset, buf, eos);

            let message_len = self.header.peek().expect("never fails").1;
            track!(self.attributes.set_expected_bytes(u64::from(message_len)))?;
        }
        bytecodec_try_decode!(self.attributes, offset, buf, eos);
        Ok(offset)
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let (message_type, _, transaction_id) = track!(self.header.finish_decoding())?;
        // TODO: call validate method
        let attributes = track!(self.attributes.finish_decoding())?;
        Ok(Message {
            class: message_type.class,
            method: track!(M::from_u12(message_type.method))?,
            transaction_id,
            attributes,
        })
    }

    fn requiring_bytes(&self) -> ByteCount {
        self.header
            .requiring_bytes()
            .add_for_decoding(self.attributes.requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.header.is_idle() && self.attributes.is_idle()
    }
}

pub struct MessageEncoder<M: Method, A: AttrValue> {
    message_type: U16beEncoder,
    message_len: U16beEncoder,
    magic_cookie: U32beEncoder,
    transaction_id: BytesEncoder<TransactionId>,
    attributes: PreEncode<Repeat<AttrEncoder<A>, vec::IntoIter<Attr<A>>>>,
    _phantom: PhantomData<M>,
}
impl<M: Method, A: AttrValue> Default for MessageEncoder<M, A> {
    fn default() -> Self {
        MessageEncoder {
            message_type: Default::default(),
            message_len: Default::default(),
            magic_cookie: Default::default(),
            transaction_id: Default::default(),
            attributes: Default::default(),
            _phantom: Default::default(),
        }
    }
}
impl<M: Method, A: AttrValue> Encode for MessageEncoder<M, A> {
    type Item = Message<M, A>;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        bytecodec_try_encode!(self.message_type, offset, buf, eos);
        bytecodec_try_encode!(self.message_len, offset, buf, eos);
        bytecodec_try_encode!(self.magic_cookie, offset, buf, eos);
        bytecodec_try_encode!(self.transaction_id, offset, buf, eos);
        bytecodec_try_encode!(self.attributes, offset, buf, eos);
        Ok(offset)
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        let ty = Type {
            class: item.class,
            method: item.method.as_u12(),
        };
        track!(self.message_type.start_encoding(ty.as_u16()))?;
        track!(self.magic_cookie.start_encoding(MAGIC_COOKIE))?;
        track!(self.transaction_id.start_encoding(item.transaction_id))?;
        track!(self.attributes.start_encoding(item.attributes.into_iter()))?;

        // TODO: check length
        let message_len = self.attributes.exact_requiring_bytes();
        track!(self.message_len.start_encoding(message_len as u16))?;
        Ok(())
    }

    fn requiring_bytes(&self) -> ByteCount {
        ByteCount::Finite(self.exact_requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.message_type.is_idle()
            && self.message_len.is_idle()
            && self.magic_cookie.is_idle()
            && self.transaction_id.is_idle()
            && self.attributes.is_idle()
    }
}
impl<M: Method, A: AttrValue> SizedEncode for MessageEncoder<M, A> {
    fn exact_requiring_bytes(&self) -> u64 {
        self.message_type.exact_requiring_bytes()
            + self.message_len.exact_requiring_bytes()
            + self.magic_cookie.exact_requiring_bytes()
            + self.transaction_id.exact_requiring_bytes()
            + self.attributes.exact_requiring_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Type {
    pub class: Class,
    pub method: U12,
}
impl Type {
    pub fn as_u16(&self) -> u16 {
        let class = self.class as u16;
        let method = self.method.as_u16();
        ((method & 0b0000_0000_1111) << 0)
            | ((class & 0b01) << 4)
            | ((method & 0b0000_0111_0000) << 5)
            | ((class & 0b10) << 7)
            | ((method & 0b1111_1000_0000) << 9)
    }

    pub fn from_u16(value: u16) -> Result<Self> {
        track_assert!(
            value >> 14 == 0,
            ErrorKind::InvalidInput,
            "First two-bits of STUN message must be 0"
        );
        let class = ((value >> 4) & 0b01) | ((value >> 7) & 0b10);
        let class = Class::from_u8(class as u8).unwrap();
        let method = (value & 0b0000_0000_1111)
            | ((value >> 1) & 0b0000_0111_0000)
            | ((value >> 2) & 0b1111_1000_0000);
        let method = U12::from_u16(method).expect("never fails");
        Ok(Type {
            class: class,
            method: method,
        })
    }
}
