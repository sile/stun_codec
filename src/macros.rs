pub use trackable::{track, track_assert, track_panic};

/// Defines an aggregated attribute type and its decoder and encoder.
#[macro_export]
macro_rules! define_attribute_enums {
    ($attr:ident, $decoder:ident, $encoder:ident,[$($variant:ident),*]) => {
        /// Attribute set.
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $attr {
            $($variant($variant)),*
        }
        $(impl From<$variant> for $attr {
            fn from(f: $variant) -> Self {
                $attr::$variant(f)
            }
        })*
        $(impl $crate::convert::TryAsRef<$variant> for $attr {
            fn try_as_ref(&self) -> Option<&$variant> {
                if let $attr::$variant(a) = self {
                    Some(a)
                } else {
                    None
                }
            }
        })*
        impl $crate::Attribute for $attr {
            type Decoder = $decoder;
            type Encoder = $encoder;

            fn get_type(&self) -> $crate::AttributeType {
                match self {
                    $($attr::$variant(a) => a.get_type()),*
                }
            }

            fn before_encode<A>(&mut self, message: &$crate::Message<A>) -> ::bytecodec::Result<()>
            where
                A: $crate::Attribute,
            {
                match self {
                    $($attr::$variant(a) => $crate::macros::track!(a.before_encode(message), "attr={}", stringify!($variant))),*
                }
            }

            fn after_decode<A>(&mut self, message: &$crate::Message<A>) -> ::bytecodec::Result<()>
            where
                A: $crate::Attribute,
            {
                match self {
                    $($attr::$variant(a) => $crate::macros::track!(a.after_decode(message), "attr={}", stringify!($variant))),*
                }
            }
        }

        /// Attribute set decoder.
        #[allow(missing_docs)]
        #[derive(Debug)]
        pub enum $decoder {
            $($variant(<$variant as $crate::Attribute>::Decoder)),*,
            None,
        }
        impl $decoder {
            /// Makes a new decoder instance.
            pub fn new() -> Self {
                Self::default()
            }
        }
        impl Default for $decoder {
            fn default() -> Self {
                $decoder::None
            }
        }
        impl ::bytecodec::Decode for $decoder {
            type Item = $attr;

            fn decode(&mut self, buf: &[u8], eos: ::bytecodec::Eos) -> ::bytecodec::Result<usize> {
                match self {
                    $($decoder::$variant(a) => $crate::macros::track!(a.decode(buf, eos), "attr={}", stringify!($variant))),*,
                    $decoder::None => $crate::macros::track_panic!(::bytecodec::ErrorKind::InconsistentState),
                }
            }

            fn finish_decoding(&mut self) -> ::bytecodec::Result<Self::Item> {
                let item = match self {
                    $($decoder::$variant(a) => $crate::macros::track!(a.finish_decoding(), "attr={}", stringify!($variant))?.into()),*,
                    $decoder::None => $crate::macros::track_panic!(::bytecodec::ErrorKind::IncompleteDecoding),
                };
                *self = $decoder::None;
                Ok(item)
            }

            fn requiring_bytes(&self) -> ::bytecodec::ByteCount {
                match self {
                    $($decoder::$variant(a) => a.requiring_bytes()),*,
                    $decoder::None => ::bytecodec::ByteCount::Finite(0),
                }
            }

            fn is_idle(&self) -> bool {
                match self {
                    $($decoder::$variant(a) => a.is_idle()),*,
                    $decoder::None => true,
                }
            }
        }
        impl ::bytecodec::TryTaggedDecode for $decoder {
            type Tag = $crate::AttributeType;

            fn try_start_decoding(&mut self, tag: Self::Tag) -> ::bytecodec::Result<bool> {
                *self = match tag.as_u16() {
                    $($variant::CODEPOINT => $decoder::$variant(<$variant as $crate::Attribute>::Decoder::default())),*,
                    _ => return Ok(false),
                };
                Ok(true)
            }
        }

        /// Attribute set encoder.
        #[allow(missing_docs)]
        #[derive(Debug)]
        pub enum $encoder {
            $($variant(<$variant as $crate::Attribute>::Encoder)),*,
            None,
        }
        impl $encoder {
            /// Makes a new encoder instance.
            pub fn new() -> Self {
                Self::default()
            }
        }
        impl Default for $encoder {
            fn default() -> Self {
                $encoder::None
            }
        }
        impl ::bytecodec::Encode for $encoder {
            type Item = $attr;

            fn encode(&mut self, buf: &mut [u8], eos: ::bytecodec::Eos) -> ::bytecodec::Result<usize> {
                match self {
                    $($encoder::$variant(a) => $crate::macros::track!(a.encode(buf, eos), "attr={}", stringify!($variant))),*,
                    $encoder::None => Ok(0),
                }
            }

            fn start_encoding(&mut self, item: Self::Item) -> ::bytecodec::Result<()> {
                $crate::macros::track_assert!(self.is_idle(), ::bytecodec::ErrorKind::EncoderFull; item);
                *self = match item {
                    $($attr::$variant(a) => {
                        let mut encoder = <$variant as $crate::Attribute>::Encoder::default();
                        $crate::macros::track!(encoder.start_encoding(a), "attr={}", stringify!($variant))?;
                        $encoder::$variant(encoder)
                    }),*
                };
                Ok(())
            }

            fn requiring_bytes(&self) -> ::bytecodec::ByteCount {
                use ::bytecodec::SizedEncode;
                ::bytecodec::ByteCount::Finite(self.exact_requiring_bytes())
            }

            fn is_idle(&self) -> bool {
                match self {
                    $($encoder::$variant(a) => a.is_idle()),*,
                    $encoder::None => true,
                }
            }
        }
        impl ::bytecodec::SizedEncode for $encoder {
            fn exact_requiring_bytes(&self) -> u64 {
                match self {
                    $($encoder::$variant(a) => a.exact_requiring_bytes()),*,
                    $encoder::None => 0,
                }
            }
        }
    };
}
