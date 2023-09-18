//! Attributes that are defined in [RFC 8016].
//!
//! [RFC 8016]: https://tools.ietf.org/html/rfc8016

use bytecodec::bytes::{BytesEncoder, RemainingBytesDecoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, Result, SizedEncode, TryTaggedDecode};

use crate::attribute::{Attribute, AttributeType};

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

/// `MOBILITY-TICKET` attribute.
///
/// See [Mobility with TURN RFC] about this attribute.
///
/// [Mobility with TURN RFC]: https://www.rfc-editor.org/rfc/rfc8016.html
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MobilityTicket(Vec<u8>);
impl MobilityTicket {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x8030;

    /// Makes a new, filled `MobilityTicket` instance.
    ///
    /// Fails on exceeding length.
    pub fn new(data: Vec<u8>) -> Result<Self> {
        //track_assert!(data.len() <= 0xFFFF, ErrorKind::InvalidInput);
        Ok(MobilityTicket(data))
    }

    /// Makes a new, empty `MobilityTicket` for requesting mobility during creating allocation.
    pub fn empty() -> Self {
        MobilityTicket(Vec::new())
    }

    /// Returns a reference the data held by the attribute.
    pub fn data(&self) -> &[u8] {
        &self.0
    }
}
impl Attribute for MobilityTicket {
    type Decoder = MobilityTicketDecoder;
    type Encoder = MobilityTicketEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`Data`] decoder.
#[derive(Debug, Default)]
pub struct MobilityTicketDecoder(RemainingBytesDecoder);
impl MobilityTicketDecoder {
    /// Makes a new `DataDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(MobilityTicketDecoder, MobilityTicket, |item| Ok(
    MobilityTicket(item)
));

/// [`Data`] encoder.
#[derive(Debug, Default)]
pub struct MobilityTicketEncoder(BytesEncoder);
impl MobilityTicketEncoder {
    /// Makes a new `DataEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(MobilityTicketEncoder, MobilityTicket, |item: Self::Item| {
    item.0
});
