//! Attributes that are defined in [RFC 5766 -- 14. New STUN Attributes].
//!
//! [RFC 5766 -- 14. New STUN Attributes]: https://tools.ietf.org/html/rfc5766#section-14

use crate::attribute::{Attribute, AttributeType};
use crate::message::Message;
use crate::net::{socket_addr_xor, SocketAddrDecoder, SocketAddrEncoder};
use bytecodec::bytes::{BytesEncoder, RemainingBytesDecoder};
use bytecodec::fixnum::{
    U32beDecoder, U32beEncoder, U64beDecoder, U64beEncoder, U8Decoder, U8Encoder,
};
use bytecodec::null::{NullDecoder, NullEncoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, ErrorKind, Result, SizedEncode, TryTaggedDecode};
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

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

/// `CHANNEL-NUMBER` attribute.
///
/// See [RFC 5766 -- 14.1. CHANNEL-NUMBER] about this attribute.
///
/// [RFC 5766 -- 14.1. CHANNEL-NUMBER]: https://tools.ietf.org/html/rfc5766#section-14.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelNumber(u16);
impl ChannelNumber {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x000C;

    /// Minimum channel number.
    pub const MIN: u16 = 0x4000;

    /// Maximum channel number.
    pub const MAX: u16 = 0x4FFF;

    /// Makes a new `ChannelNumber` instance.
    ///
    ///
    /// # Errors
    ///
    /// If `n` is not a number between `ChannelNumber::MIN` and `ChannelNumber::MAX`,
    /// this will return an `ErrorKind::InvalidInput` error.
    pub fn new(n: u16) -> Result<Self> {
        track_assert!(n >= Self::MIN, ErrorKind::InvalidInput; n);
        track_assert!(n <= Self::MAX, ErrorKind::InvalidInput; n);
        Ok(ChannelNumber(n))
    }

    /// Returns the channel number indicated by the attribute.
    pub fn value(self) -> u16 {
        self.0
    }

    /// Returns the minimum channel number.
    pub fn min() -> Self {
        ChannelNumber(Self::MIN)
    }

    /// Returns the maximum channel number.
    pub fn max() -> Self {
        ChannelNumber(Self::MAX)
    }

    /// Wrapping incrementation.
    pub fn wrapping_increment(self) -> Self {
        if self.0 == Self::MAX {
            Self::min()
        } else {
            ChannelNumber(self.0 + 1)
        }
    }
}
impl Attribute for ChannelNumber {
    type Decoder = ChannelNumberDecoder;
    type Encoder = ChannelNumberEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

impl fmt::Display for ChannelNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// [`ChannelNumber`] decoder.
#[derive(Debug, Default)]
pub struct ChannelNumberDecoder(U32beDecoder);
impl ChannelNumberDecoder {
    /// Makes a new `ChannelNumberDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(ChannelNumberDecoder, ChannelNumber, |item| track!(
    ChannelNumber::new((item >> 16) as u16)
));

/// [`ChannelNumber`] encoder.
#[derive(Debug, Default)]
pub struct ChannelNumberEncoder(U32beEncoder);
impl ChannelNumberEncoder {
    /// Makes a new `ChannelNumberEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    ChannelNumberEncoder,
    ChannelNumber,
    |item: Self::Item| u32::from(item.0) << 16
);

/// `LIFETIME` attribute.
///
/// See [RFC 5766 -- 14.2. LIFETIME] about this attribute.
///
/// [RFC 5766 -- 14.2. LIFETIME]: https://tools.ietf.org/html/rfc5766#section-14.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Lifetime(Duration);
impl Lifetime {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x000D;

    /// Makes a new `Lifetime` instance.
    ///
    /// Note that the nanoseconds part of `lifetime` is ignored and always set to `0`.
    ///
    /// # Errors
    ///
    /// If the seconds part of `lifetime` is greater than `0xFFFF_FFFF`,
    /// this function will return an `ErrorKind::InvalidInput` error.
    pub fn new(lifetime: Duration) -> Result<Self> {
        let lifetime_seconds = lifetime.as_secs();
        track_assert!(lifetime_seconds <= 0xFFFF_FFFF, ErrorKind::InvalidInput);
        Ok(Lifetime(Duration::from_secs(lifetime_seconds)))
    }

    /// Makes a new `Lifetime` instance from `u32` value.
    pub fn from_u32(lifetime_seconds: u32) -> Self {
        Lifetime(Duration::from_secs(u64::from(lifetime_seconds)))
    }

    /// Returns the lifetime indicated by the attribute.
    pub fn lifetime(&self) -> Duration {
        self.0
    }
}
impl Attribute for Lifetime {
    type Decoder = LifetimeDecoder;
    type Encoder = LifetimeEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`Lifetime`] decoder.
#[derive(Debug, Default)]
pub struct LifetimeDecoder(U32beDecoder);
impl LifetimeDecoder {
    /// Makes a new `LifetimeDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(LifetimeDecoder, Lifetime, |item| Ok(Lifetime(
    Duration::from_secs(u64::from(item))
)));

/// [`Lifetime`] encoder.
#[derive(Debug, Default)]
pub struct LifetimeEncoder(U32beEncoder);
impl LifetimeEncoder {
    /// Makes a new `LifetimeEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    LifetimeEncoder,
    Lifetime,
    |item: Self::Item| item.0.as_secs() as u32
);

/// `XOR-PEER-ADDRESS` attribute.
///
/// See [RFC 5766 -- 14.3. XOR-PEER-ADDRESS] about this attribute.
///
/// [RFC 5766 -- 14.3. XOR-PEER-ADDRESS]: https://tools.ietf.org/html/rfc5766#section-14.3
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XorPeerAddress(SocketAddr);
impl XorPeerAddress {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0012;

    /// Makes a new `XorPeerAddress` instance.
    pub fn new(addr: SocketAddr) -> Self {
        XorPeerAddress(addr)
    }

    /// Returns the address specified by the attribute.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl Attribute for XorPeerAddress {
    type Decoder = XorPeerAddressDecoder;
    type Encoder = XorPeerAddressEncoder;

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

/// [`XorPeerAddress`] decoder.
#[derive(Debug, Default)]
pub struct XorPeerAddressDecoder(SocketAddrDecoder);
impl XorPeerAddressDecoder {
    /// Makes a new `XorPeerAddressDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(XorPeerAddressDecoder, XorPeerAddress, |item| Ok(
    XorPeerAddress(item)
));

/// [`XorPeerAddress`] encoder.
#[derive(Debug, Default)]
pub struct XorPeerAddressEncoder(SocketAddrEncoder);
impl XorPeerAddressEncoder {
    /// Makes a new `XorPeerAddressEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(XorPeerAddressEncoder, XorPeerAddress, |item: Self::Item| {
    item.0
});

/// `DATA` attribute.
///
/// See [RFC 5766 -- 14.4. DATA] about this attribute.
///
/// [RFC 5766 -- 14.4. DATA]: https://tools.ietf.org/html/rfc5766#section-14.4
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Data(Vec<u8>);
impl Data {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0013;

    /// Makes a new `Data` instance.
    ///
    /// # Errors
    ///
    /// If the length of `data` is greater than `0xFFFF`,
    /// this function will return an `ErrorKind::InvalidInput` error.
    pub fn new(data: Vec<u8>) -> Result<Self> {
        track_assert!(data.len() <= 0xFFFF, ErrorKind::InvalidInput);
        Ok(Data(data))
    }

    /// Returns a reference the data held by the attribute.
    pub fn data(&self) -> &[u8] {
        &self.0
    }
}
impl Attribute for Data {
    type Decoder = DataDecoder;
    type Encoder = DataEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`Data`] decoder.
#[derive(Debug, Default)]
pub struct DataDecoder(RemainingBytesDecoder);
impl DataDecoder {
    /// Makes a new `DataDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(DataDecoder, Data, |item| Ok(Data(item)));

/// [`Data`] encoder.
#[derive(Debug, Default)]
pub struct DataEncoder(BytesEncoder);
impl DataEncoder {
    /// Makes a new `DataEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(DataEncoder, Data, |item: Self::Item| item.0);

/// `XOR-RELAY-ADDRESS` attribute.
///
/// See [RFC 5766 -- 14.5. XOR-RELAY-ADDRESS] about this attribute.
///
/// [RFC 5766 -- 14.5. XOR-RELAY-ADDRESS]: https://tools.ietf.org/html/rfc5766#section-14.5
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XorRelayAddress(SocketAddr);
impl XorRelayAddress {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0016;

    /// Makes a new `XorRelayAddress` instance.
    pub fn new(addr: SocketAddr) -> Self {
        XorRelayAddress(addr)
    }

    /// Returns the address specified by the attribute.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl Attribute for XorRelayAddress {
    type Decoder = XorRelayAddressDecoder;
    type Encoder = XorRelayAddressEncoder;

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

/// [`XorRelayAddress`] decoder.
#[derive(Debug, Default)]
pub struct XorRelayAddressDecoder(SocketAddrDecoder);
impl XorRelayAddressDecoder {
    /// Makes a new `XorRelayAddressDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(XorRelayAddressDecoder, XorRelayAddress, |item| Ok(
    XorRelayAddress(item)
));

/// [`XorRelayAddress`] encoder.
#[derive(Debug, Default)]
pub struct XorRelayAddressEncoder(SocketAddrEncoder);
impl XorRelayAddressEncoder {
    /// Makes a new `XorRelayAddressEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    XorRelayAddressEncoder,
    XorRelayAddress,
    |item: Self::Item| item.0
);

/// `EVEN-PORT` attribute.
///
/// See [RFC 5766 -- 14.6. EVEN-PORT] about this attribute.
///
/// [RFC 5766 -- 14.6. EVEN-PORT]: https://tools.ietf.org/html/rfc5766#section-14.6
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvenPort(bool);
impl EvenPort {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0018;

    /// Makes a new `EvenPort` instance.
    pub fn new(is_requested: bool) -> Self {
        EvenPort(is_requested)
    }

    /// Returns whether the client requested that the port in the relayed transport address be even.
    pub fn is_requested(&self) -> bool {
        self.0
    }
}
impl Attribute for EvenPort {
    type Decoder = EvenPortDecoder;
    type Encoder = EvenPortEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`EvenPort`] decoder.
#[derive(Debug, Default)]
pub struct EvenPortDecoder(U8Decoder);
impl EvenPortDecoder {
    /// Makes a new `EvenPortDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(EvenPortDecoder, EvenPort, |item| Ok(EvenPort(
    (item & 0b1000_0000) != 0
)));

/// [`EvenPort`] encoder.
#[derive(Debug, Default)]
pub struct EvenPortEncoder(U8Encoder);
impl EvenPortEncoder {
    /// Makes a new `EvenPortEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(EvenPortEncoder, EvenPort, |item: Self::Item| u8::from(
    item.0
) << 7);

/// `REQUESTED-TRANSPORT` attribute.
///
/// See [RFC 5766 -- 14.7. REQUESTED-TRANSPORT] about this attribute.
///
/// [RFC 5766 -- 14.7. REQUESTED-TRANSPORT]: https://tools.ietf.org/html/rfc5766#section-14.7
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestedTransport(u8);
impl RequestedTransport {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0019;

    /// Makes a new `RequestedTransport` instance.
    pub fn new(protocol: u8) -> Self {
        RequestedTransport(protocol)
    }

    /// Returns the transport protocol requested by the client.
    pub fn protocol(&self) -> u8 {
        self.0
    }
}
impl Attribute for RequestedTransport {
    type Decoder = RequestedTransportDecoder;
    type Encoder = RequestedTransportEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`RequestedTransport`] decoder.
#[derive(Debug, Default)]
pub struct RequestedTransportDecoder(U32beDecoder);
impl RequestedTransportDecoder {
    /// Makes a new `RequestedTransportDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(RequestedTransportDecoder, RequestedTransport, |item| Ok(
    RequestedTransport((item >> 24) as u8)
));

/// [`RequestedTransport`] encoder.
#[derive(Debug, Default)]
pub struct RequestedTransportEncoder(U32beEncoder);
impl RequestedTransportEncoder {
    /// Makes a new `RequestedTransportEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    RequestedTransportEncoder,
    RequestedTransport,
    |item: Self::Item| u32::from(item.0) << 24
);

/// `DONT-FRAGMENT` attribute.
///
/// See [RFC 5766 -- 14.8. DONT-FRAGMENT] about this attribute.
///
/// [RFC 5766 -- 14.8. DONT-FRAGMENT]: https://tools.ietf.org/html/rfc5766#section-14.8
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DontFragment;
impl DontFragment {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x001A;
}
impl Attribute for DontFragment {
    type Decoder = DontFragmentDecoder;
    type Encoder = DontFragmentEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`DontFragment`] decoder.
#[derive(Debug, Default)]
pub struct DontFragmentDecoder(NullDecoder);
impl DontFragmentDecoder {
    /// Makes a new `DontFragmentDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(DontFragmentDecoder, DontFragment, |()| Ok(DontFragment));

/// [`DontFragment`] encoder.
#[derive(Debug, Default)]
pub struct DontFragmentEncoder(NullEncoder);
impl DontFragmentEncoder {
    /// Makes a new `DontFragmentEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(DontFragmentEncoder, DontFragment, |_: Self::Item| ());

/// `RESERVATION-TOKEN` attribute.
///
/// See [RFC 5766 -- 14.9. RESERVATION-TOKEN] about this attribute.
///
/// [RFC 5766 -- 14.9. RESERVATION-TOKEN]: https://tools.ietf.org/html/rfc5766#section-14.9
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReservationToken(u64);
impl ReservationToken {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0022;

    /// Makes a new `ReservationToken` instance.
    pub fn new(token: u64) -> Self {
        ReservationToken(token)
    }

    /// Returns the token value contained by the attribute.
    pub fn token(&self) -> u64 {
        self.0
    }
}
impl Attribute for ReservationToken {
    type Decoder = ReservationTokenDecoder;
    type Encoder = ReservationTokenEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`ReservationToken`] decoder.
#[derive(Debug, Default)]
pub struct ReservationTokenDecoder(U64beDecoder);
impl ReservationTokenDecoder {
    /// Makes a new `ReservationTokenDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(ReservationTokenDecoder, ReservationToken, |item| Ok(
    ReservationToken(item)
));

/// [`ReservationToken`] encoder.
#[derive(Debug, Default)]
pub struct ReservationTokenEncoder(U64beEncoder);
impl ReservationTokenEncoder {
    /// Makes a new `ReservationTokenEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(
    ReservationTokenEncoder,
    ReservationToken,
    |item: Self::Item| item.0
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_byte_of_channel_number_is_in_range() {
        let range = 64..=79;

        // As per <https://www.rfc-editor.org/rfc/rfc8656#name-channels-2>.
        assert!(range.contains(&ChannelNumber::MIN.to_be_bytes()[0]));
        assert!(range.contains(&ChannelNumber::MAX.to_be_bytes()[0]));
    }
}
