//! Attributes that are defined in [RFC 5780].
//!
//! [RFC 5780]: https://tools.ietf.org/html/rfc5780

use std::net::SocketAddr;

use bytecodec::fixnum::{U32beDecoder, U32beEncoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, Result, SizedEncode, TryTaggedDecode};

use crate::attribute::{Attribute, AttributeType};
use crate::net::{SocketAddrDecoder, SocketAddrEncoder};

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
                track!(self.0.start_encoding($map_from(item).into()))
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

/// `CHANGE-REQUEST` attribute.
///
/// See [RFC 5780 -- 7.2. CHANGE-REQUEST] about this attribute.
///
/// [RFC 5780 -- 7.2. CHANGE-REQUEST]: https://tools.ietf.org/html/rfc5780#section-7.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangeRequest(bool, bool);

impl ChangeRequest {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0003;

    /// Makes a new `ChangeRequest` instance.
    pub fn new(ip: bool, port: bool) -> Self {
        ChangeRequest(ip, port)
    }

    /// Returns whether the client requested the server to send the Binding Response with a
    /// different IP address than the one the Binding Request was received on
    pub fn ip(&self) -> bool {
        self.0
    }

    /// Returns whether the client requested the server to send the Binding Response with a
    /// different port than the one the Binding Request was received on
    pub fn port(&self) -> bool {
        self.1
    }
}

impl Attribute for ChangeRequest {
    type Decoder = ChangeRequestDecoder;
    type Encoder = ChangeRequestEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`ChangeRequest`] decoder.
#[derive(Debug, Default)]
pub struct ChangeRequestDecoder(U32beDecoder);

impl ChangeRequestDecoder {
    /// Makes a new `ChangeRequestDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(ChangeRequestDecoder, ChangeRequest, |item| {
    Ok(ChangeRequest((item & 0x2) != 0, (item & 0x1) != 0))
});

/// [`ChangeRequest`] encoder.
#[derive(Debug, Default)]
pub struct ChangeRequestEncoder(U32beEncoder);

impl ChangeRequestEncoder {
    /// Makes a new `ChangeRequestEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(ChangeRequestEncoder, ChangeRequest, |item: Self::Item| {
    let ip = item.0 as u8;
    let port = item.1 as u8;
    ((ip << 1 | port) << 1) as u32
});

/// `RESPONSE-ORIGIN` attribute.
///
/// See [RFC 5780 -- 7.3. RESPONSE-ORIGIN] about this attribute.
///
/// [RFC 5780 -- 7.3. RESPONSE-ORIGIN]: https://tools.ietf.org/html/rfc5780#section-7.3
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResponseOrigin(SocketAddr);

impl ResponseOrigin {
    /// The codepoint of the tyep of the attribute.
    pub const CODEPOINT: u16 = 0x802b;

    /// Makes a new `ResponseOrigin` instance.
    pub fn new(addr: SocketAddr) -> Self {
        ResponseOrigin(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}

impl Attribute for ResponseOrigin {
    type Decoder = ResponseOriginDecoder;
    type Encoder = ResponseOriginEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`ResponseOrigin`] decoder.
#[derive(Debug, Default)]
pub struct ResponseOriginDecoder(SocketAddrDecoder);

impl ResponseOriginDecoder {
    /// Makes a new `ResponseOriginDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(ResponseOriginDecoder, ResponseOrigin, |item| Ok(
    ResponseOrigin(item)
));

/// [`ResponseOrigin`] encoder.
///
/// [`ResponseOrigin`]: ./struct.ResponseOrigin.html
#[derive(Debug, Default)]
pub struct ResponseOriginEncoder(SocketAddrEncoder);

impl ResponseOriginEncoder {
    /// Makes a new `ResponseOriginEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(ResponseOriginEncoder, ResponseOrigin, |item: Self::Item| {
    item.0
});

/// `OTHER-ADDRESS` attribute.
///
/// See [RFC 5780 -- 7.4. OTHER-ADDRESS] about this attribute.
///
/// [RFC 5780 -- 7.4. OTHER-ADDRESS]: https://tools.ietf.org/html/rfc5780#section-7.4
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OtherAddress(SocketAddr);

impl OtherAddress {
    /// The codepoint of the tyep of the attribute.
    pub const CODEPOINT: u16 = 0x802c;

    /// Makes a new `OtherAddress` instance.
    pub fn new(addr: SocketAddr) -> Self {
        OtherAddress(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}

impl Attribute for OtherAddress {
    type Decoder = OtherAddressDecoder;
    type Encoder = OtherAddressEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`OtherAddress`] decoder.
#[derive(Debug, Default)]
pub struct OtherAddressDecoder(SocketAddrDecoder);

impl OtherAddressDecoder {
    /// Makes a new `OtherAddressDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(OtherAddressDecoder, OtherAddress, |item| Ok(OtherAddress(
    item
)));

/// [`OtherAddress`] encoder.
#[derive(Debug, Default)]
pub struct OtherAddressEncoder(SocketAddrEncoder);

impl OtherAddressEncoder {
    /// Makes a new `OtherAddressEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(OtherAddressEncoder, OtherAddress, |item: Self::Item| item.0);

/// `RESPONSE-PORT` attribute.
///
/// See [RFC 5780 -- 7.5. RESPONSE-PORT] about this attribute.
///
/// [RFC 5780 -- 7.5. RESPONSE-PORT]: https://tools.ietf.org/html/rfc5780#section-7.5
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResponsePort(u16);

impl ResponsePort {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0027;

    /// Makes a new `ResponsePort` instance.
    pub fn new(port: u16) -> Self {
        ResponsePort(port)
    }

    /// Returns the address of this instance.
    pub fn port(&self) -> u16 {
        self.0
    }
}

impl Attribute for ResponsePort {
    type Decoder = ResponsePortDecoder;
    type Encoder = ResponsePortEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`ResponsePort`] decoder.
#[derive(Debug, Default)]
pub struct ResponsePortDecoder(U32beDecoder);

impl ResponsePortDecoder {
    /// Makes a new `ResponsePortDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(ResponsePortDecoder, ResponsePort, |item| Ok(
    ResponsePort::new((item >> 16) as u16)
));

/// [`ResponsePort`] encoder.
#[derive(Debug, Default)]
pub struct ResponsePortEncoder(U32beEncoder);

impl ResponsePortEncoder {
    /// Makes a new `ResponsePortEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(ResponsePortEncoder, ResponsePort, |_item: Self::Item| 0u16);
