use bytecodec::bytes::{Utf8Decoder, Utf8Encoder};
use bytecodec::fixnum::{U32beDecoder, U32beEncoder};
use bytecodec::tuple::{TupleDecoder, TupleEncoder};
use bytecodec::{ByteCount, Decode, Encode, EncodeExt, Eos, ErrorKind, Result, SizedEncode};
use crc::crc32;
use std::net::SocketAddr;

use attribute::{AttrType, AttrValue, AttrValueDecode};
use message::{Message, MessageEncoder, Method};
use types::{SocketAddrDecoder, SocketAddrEncoder};

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
        impl AttrValueDecode for $decoder {
            fn start_decoding(&mut self, attr_type: AttrType) -> Result<()> {
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
    reason_phrase: String,
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
        bytes[2] = (final_len >> 8) as u8;
        bytes[3] = final_len as u8;
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
