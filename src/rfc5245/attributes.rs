//! Attributes that are defined in [RFC 5245].
//!
//! [RFC 5245]: https://tools.ietf.org/html/rfc5245
use crate::attribute::{Attribute, AttributeType};
use bytecodec::fixnum::{U32beDecoder, U32beEncoder, U64beDecoder, U64beEncoder};
use bytecodec::null::{NullDecoder, NullEncoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, Result, SizedEncode, TryTaggedDecode};

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

/// `PRIORITY` attribute.
///
/// See [RFC 5245 -- 7.1.2.1 PRIORITY] about this attribute.
///
/// [RFC 5245 -- 7.1.2.1 PRIORITY]: https://tools.ietf.org/html/rfc5245#section-7.1.2.1
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Priority(u32);
impl Priority {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0024;

    /// Makes a new `Priority` instance.
    pub fn new(prio: u32) -> Self {
        Priority(prio)
    }

    /// Returns the alternate address.
    pub fn prio(&self) -> u32 {
        self.0
    }
}
impl Attribute for Priority {
    type Decoder = PriorityDecoder;
    type Encoder = PriorityEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`Priority`] decoder.
#[derive(Debug, Default)]
pub struct PriorityDecoder(U32beDecoder);

impl PriorityDecoder {
    /// Makes a new `PriorityDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(PriorityDecoder, Priority, |prio| Ok(Priority(prio)));

/// [`Priority`] encoder.
#[derive(Debug, Default)]
pub struct PriorityEncoder(U32beEncoder);

impl PriorityEncoder {
    /// Makes a new `PriorityEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(PriorityEncoder, Priority, |item: Self::Item| item.0);

/// `USE-CANDIDATE` attribute.
///
/// See [RFC 5245 -- 7.1.2.1 USE-CANDIDATE] about this attribute.
///
/// [RFC 5245 -- 7.1.2.1 USE-CANDIDATE]: https://tools.ietf.org/html/rfc5245#section-7.1.2.1
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UseCandidate;
impl UseCandidate {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0025;

    /// Makes a new `UseCandidate` instance.
    pub fn new() -> Self {
        UseCandidate
    }
}
impl Attribute for UseCandidate {
    type Decoder = UseCandidateDecoder;
    type Encoder = UseCandidateEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}
impl Default for UseCandidate {
    fn default() -> Self {
        Self::new()
    }
}

/// [`UseCandidate`] decoder.
#[derive(Debug, Default)]
pub struct UseCandidateDecoder(NullDecoder);

impl UseCandidateDecoder {
    /// Makes a new `UseCandidateDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(UseCandidateDecoder, UseCandidate, |_| Ok(UseCandidate));

/// [`UseCandidate`] encoder.
#[derive(Debug, Default)]
pub struct UseCandidateEncoder(NullEncoder);

impl UseCandidateEncoder {
    /// Makes a new `UseCandidateEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(UseCandidateEncoder, UseCandidate, |_item: Self::Item| ());

/// `ICE-CONTROLLED` attribute.
///
/// See [RFC 5245 -- 7.1.2.1 ICE-CONTROLLED] about this attribute.
///
/// [RFC 5245 -- 7.1.2.1 ICE-CONTROLLED]: https://tools.ietf.org/html/rfc5245#section-7.1.2.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceControlled(u64);
impl IceControlled {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x8029;

    /// Makes a new `IceControlled` instance.
    pub fn new(rnd: u64) -> Self {
        IceControlled(rnd)
    }

    /// Returns the alternate address.
    pub fn prio(&self) -> u64 {
        self.0
    }
}
impl Attribute for IceControlled {
    type Decoder = IceControlledDecoder;
    type Encoder = IceControlledEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`IceControlled`] decoder.
#[derive(Debug, Default)]
pub struct IceControlledDecoder(U64beDecoder);

impl IceControlledDecoder {
    /// Makes a new `IceControlledDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(IceControlledDecoder, IceControlled, |prio| Ok(
    IceControlled(prio)
));

/// [`IceControlled`] encoder.
#[derive(Debug, Default)]
pub struct IceControlledEncoder(U64beEncoder);

impl IceControlledEncoder {
    /// Makes a new `IceControlledEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(IceControlledEncoder, IceControlled, |item: Self::Item| item
    .0);

/// `ICE-CONTROLLING` attribute.
///
/// See [RFC 5245 -- 7.1.2.1 ICE-CONTROLLING] about this attribute.
///
/// [RFC 5245 -- 7.1.2.1 ICE-CONTROLLING]: https://tools.ietf.org/html/rfc5245#section-7.1.2.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceControlling(u64);
impl IceControlling {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x802A;

    /// Makes a new `IceControlling` instance.
    pub fn new(rnd: u64) -> Self {
        IceControlling(rnd)
    }

    /// Returns the alternate address.
    pub fn prio(&self) -> u64 {
        self.0
    }
}
impl Attribute for IceControlling {
    type Decoder = IceControllingDecoder;
    type Encoder = IceControllingEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`IceControlling`] decoder.
#[derive(Debug, Default)]
pub struct IceControllingDecoder(U64beDecoder);

impl IceControllingDecoder {
    /// Makes a new `IceControllingDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(IceControllingDecoder, IceControlling, |prio| Ok(
    IceControlling(prio)
));

/// [`IceControlling`] encoder.
#[derive(Debug, Default)]
pub struct IceControllingEncoder(U64beEncoder);

impl IceControllingEncoder {
    /// Makes a new `IceControllingEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(IceControllingEncoder, IceControlling, |item: Self::Item| {
    item.0
});
