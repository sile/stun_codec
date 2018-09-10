//! [RFC 5766(TURN)][RFC 5766] specific components.
//!
//! [RFC 5766]: https://tools.ietf.org/html/rfc5766
use bytecodec::{
    ByteCount, Decode, Encode, EncodeExt, Eos, ErrorKind, Result, SizedEncode, TryTaggedDecode,
};

use self::attributes::*;
use rfc5389::attributes::*;
use {AttributeType, Message};

pub mod attributes;
pub mod errors;
pub mod methods;

macro_rules! impl_attribute {
    ($($attr:ident),*) => {
        $(impl From<$attr> for Attribute {
            fn from(f: $attr) -> Self {
                Attribute::$attr(f)
            }
        })*
        impl ::Attribute for Attribute {
            type Decoder = AttributeDecoder;
            type Encoder = AttributeEncoder;

            fn get_type(&self) -> AttributeType {
                match self {
                    $(Attribute::$attr(a) => a.get_type()),*
                }
            }

            fn before_encode<A>(&mut self, message: &Message<A>) -> Result<()>
            where
                A: ::Attribute,
            {
                match self {
                    $(Attribute::$attr(a) => track!(a.before_encode(message), "attr={}", stringify!($attr))),*
                }
            }

            fn after_decode<A>(&mut self, message: &Message<A>) -> Result<()>
            where
                A: ::Attribute,
            {
                match self {
                    $(Attribute::$attr(a) => track!(a.after_decode(message), "attr={}", stringify!($attr))),*
                }
            }
        }
    };
}

macro_rules! impl_attribute_decoder_inner {
    ($([$attr:ident, $decoder:ident]),*) => {
        $(impl From<$decoder> for AttributeDecoderInner {
            fn from(f: $decoder) -> Self {
                AttributeDecoderInner::$attr(f)
            }
        })*
        impl Decode for AttributeDecoderInner {
            type Item = Attribute;

            fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
                match self {
                    $(AttributeDecoderInner::$attr(a) => track!(a.decode(buf, eos), "attr={}", stringify!($attr))),*,
                    AttributeDecoderInner::None => track_panic!(ErrorKind::InconsistentState),
                }
            }

            fn finish_decoding(&mut self) -> Result<Self::Item> {
                let item = match self {
                    $(AttributeDecoderInner::$attr(a) => track!(a.finish_decoding(), "attr={}", stringify!($attr))?.into()),*,
                    AttributeDecoderInner::None => track_panic!(ErrorKind::IncompleteDecoding),
                };
                *self = AttributeDecoderInner::None;
                Ok(item)
            }

            fn requiring_bytes(&self) -> ByteCount {
                match self {
                    $(AttributeDecoderInner::$attr(a) => a.requiring_bytes()),*,
                    AttributeDecoderInner::None => ByteCount::Finite(0),
                }
            }

            fn is_idle(&self) -> bool {
                match self {
                    $(AttributeDecoderInner::$attr(a) => a.is_idle()),*,
                    AttributeDecoderInner::None => true,
                }
            }
        }
        impl TryTaggedDecode for AttributeDecoderInner {
            type Tag = AttributeType;

            fn try_start_decoding(&mut self, tag: Self::Tag) -> Result<bool> {
                *self = match tag.as_u16() {
                    $($attr::CODEPOINT => $decoder::new().into()),*,
                    _ => return Ok(false),
                };
                Ok(true)
            }
        }
    };
}

macro_rules! impl_attribute_encoder_inner {
    ($([$attr:ident, $encoder:ident]),*) => {        
        $(impl From<$encoder> for AttributeEncoderInner {
            fn from(f: $encoder) -> Self {
                AttributeEncoderInner::$attr(f)
            }
        })*
        impl Encode for AttributeEncoderInner {
            type Item = Attribute;
            
            fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
                match self {
                    $(AttributeEncoderInner::$attr(a) => track!(a.encode(buf, eos), "attr={}", stringify!($attr))),*,
                    AttributeEncoderInner::None => Ok(0),
                }
            }

            fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
                track_assert!(self.is_idle(), ErrorKind::EncoderFull; item);
                *self = match item {
                    $(Attribute::$attr(a) => track!($encoder::with_item(a), "attr={}", stringify!($attr))?.into()),*
                };
                Ok(())
            }

            fn requiring_bytes(&self) -> ByteCount {
                ByteCount::Finite(self.exact_requiring_bytes())
            }

            fn is_idle(&self) -> bool {
                match self {
                    $(AttributeEncoderInner::$attr(a) => a.is_idle()),*,
                    AttributeEncoderInner::None => true,
                }
            }
        }
        impl SizedEncode for AttributeEncoderInner {
            fn exact_requiring_bytes(&self) -> u64 {
                match self {
                    $(AttributeEncoderInner::$attr(a) => a.exact_requiring_bytes()),*,
                    AttributeEncoderInner::None => 0,
                }
            }
        }
    };
}

/// Attribute set that are defined in [RFC 5766] and [RFC 5389].
///
/// [RFC 5389]: https://tools.ietf.org/html/rfc5389
/// [RFC 5766]: https://tools.ietf.org/html/rfc5766
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Attribute {
    // RFC 5389
    MappedAddress(MappedAddress),
    Username(Username),
    MessageIntegrity(MessageIntegrity),
    ErrorCode(ErrorCode),
    UnknownAttributes(UnknownAttributes),
    Realm(Realm),
    Nonce(Nonce),
    XorMappedAddress(XorMappedAddress),
    Software(Software),
    AlternateServer(AlternateServer),
    Fingerprint(Fingerprint),

    // RFC 5766
    ChannelNumber(ChannelNumber),
    Lifetime(Lifetime),
    XorPeerAddress(XorPeerAddress),
    Data(Data),
    XorRelayAddress(XorRelayAddress),
    EvenPort(EvenPort),
    RequestedTransport(RequestedTransport),
    DontFragment(DontFragment),
    ReservationToken(ReservationToken),
}
impl_attribute!(
    MappedAddress,
    Username,
    MessageIntegrity,
    ErrorCode,
    UnknownAttributes,
    Realm,
    Nonce,
    XorMappedAddress,
    Software,
    AlternateServer,
    Fingerprint,
    ChannelNumber,
    Lifetime,
    XorPeerAddress,
    Data,
    XorRelayAddress,
    EvenPort,
    RequestedTransport,
    DontFragment,
    ReservationToken
);

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
    // RFC 5389
    MappedAddress(MappedAddressDecoder),
    Username(UsernameDecoder),
    MessageIntegrity(MessageIntegrityDecoder),
    ErrorCode(ErrorCodeDecoder),
    UnknownAttributes(UnknownAttributesDecoder),
    Realm(RealmDecoder),
    Nonce(NonceDecoder),
    XorMappedAddress(XorMappedAddressDecoder),
    Software(SoftwareDecoder),
    AlternateServer(AlternateServerDecoder),
    Fingerprint(FingerprintDecoder),

    // RFC 5766
    ChannelNumber(ChannelNumberDecoder),
    Lifetime(LifetimeDecoder),
    XorPeerAddress(XorPeerAddressDecoder),
    Data(DataDecoder),
    XorRelayAddress(XorRelayAddressDecoder),
    EvenPort(EvenPortDecoder),
    RequestedTransport(RequestedTransportDecoder),
    DontFragment(DontFragmentDecoder),
    ReservationToken(ReservationTokenDecoder),

    None,
}
impl Default for AttributeDecoderInner {
    fn default() -> Self {
        AttributeDecoderInner::None
    }
}
impl_attribute_decoder_inner!(
    [MappedAddress, MappedAddressDecoder],
    [Username, UsernameDecoder],
    [MessageIntegrity, MessageIntegrityDecoder],
    [ErrorCode, ErrorCodeDecoder],
    [UnknownAttributes, UnknownAttributesDecoder],
    [Realm, RealmDecoder],
    [Nonce, NonceDecoder],
    [XorMappedAddress, XorMappedAddressDecoder],
    [Software, SoftwareDecoder],
    [AlternateServer, AlternateServerDecoder],
    [Fingerprint, FingerprintDecoder],
    [ChannelNumber, ChannelNumberDecoder],
    [Lifetime, LifetimeDecoder],
    [XorPeerAddress, XorPeerAddressDecoder],
    [Data, DataDecoder],
    [XorRelayAddress, XorRelayAddressDecoder],
    [EvenPort, EvenPortDecoder],
    [RequestedTransport, RequestedTransportDecoder],
    [DontFragment, DontFragmentDecoder],
    [ReservationToken, ReservationTokenDecoder]
);

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
    // RFC 5389
    MappedAddress(MappedAddressEncoder),
    Username(UsernameEncoder),
    MessageIntegrity(MessageIntegrityEncoder),
    ErrorCode(ErrorCodeEncoder),
    UnknownAttributes(UnknownAttributesEncoder),
    Realm(RealmEncoder),
    Nonce(NonceEncoder),
    XorMappedAddress(XorMappedAddressEncoder),
    Software(SoftwareEncoder),
    AlternateServer(AlternateServerEncoder),
    Fingerprint(FingerprintEncoder),

    // RFC 5766
    ChannelNumber(ChannelNumberEncoder),
    Lifetime(LifetimeEncoder),
    XorPeerAddress(XorPeerAddressEncoder),
    Data(DataEncoder),
    XorRelayAddress(XorRelayAddressEncoder),
    EvenPort(EvenPortEncoder),
    RequestedTransport(RequestedTransportEncoder),
    DontFragment(DontFragmentEncoder),
    ReservationToken(ReservationTokenEncoder),

    None,
}
impl Default for AttributeEncoderInner {
    fn default() -> Self {
        AttributeEncoderInner::None
    }
}

impl_attribute_encoder_inner!(
    [MappedAddress, MappedAddressEncoder],
    [Username, UsernameEncoder],
    [MessageIntegrity, MessageIntegrityEncoder],
    [ErrorCode, ErrorCodeEncoder],
    [UnknownAttributes, UnknownAttributesEncoder],
    [Realm, RealmEncoder],
    [Nonce, NonceEncoder],
    [XorMappedAddress, XorMappedAddressEncoder],
    [Software, SoftwareEncoder],
    [AlternateServer, AlternateServerEncoder],
    [Fingerprint, FingerprintEncoder],
    [ChannelNumber, ChannelNumberEncoder],
    [Lifetime, LifetimeEncoder],
    [XorPeerAddress, XorPeerAddressEncoder],
    [Data, DataEncoder],
    [XorRelayAddress, XorRelayAddressEncoder],
    [EvenPort, EvenPortEncoder],
    [RequestedTransport, RequestedTransportEncoder],
    [DontFragment, DontFragmentEncoder],
    [ReservationToken, ReservationTokenEncoder]
);
