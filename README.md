stun_codec
===========
[![stun_codec](https://img.shields.io/crates/v/stun_codec.svg)](https://crates.io/crates/stun_codec)
[![Documentation](https://docs.rs/stun_codec/badge.svg)](https://docs.rs/stun_codec)
[![Actions Status](https://github.com/sile/stun_codec/workflows/CI/badge.svg)](https://github.com/sile/stun_codec/actions)
[![Coverage Status](https://coveralls.io/repos/github/sile/stun_codec/badge.svg?branch=master)](https://coveralls.io/github/sile/stun_codec?branch=master)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Encoders and decoders for [STUN (RFC 5389)][RFC 5389] and its extensions.

[Documentation](https://docs.rs/stun_codec)


Examples
--------

```rust
use bytecodec::{DecodeExt, EncodeExt, Error};
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};
use stun_codec::rfc5389::{attributes::Software, methods::BINDING, Attribute};

// Creates a message
let mut message = Message::new(MessageClass::Request, BINDING, TransactionId::new([3; 12]));
message.add_attribute(Attribute::Software(Software::new("foo".to_owned())?));

// Encodes the message
let mut encoder = MessageEncoder::new();
let bytes = encoder.encode_into_bytes(message.clone())?;
assert_eq!(
    bytes,
    [
        0, 1, 0, 8, 33, 18, 164, 66, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 128, 34, 0, 3,
        102, 111, 111, 0
    ]
);

// Decodes the message
let mut decoder = MessageDecoder::<Attribute>::new();
let decoded = decoder.decode_from_bytes(&bytes)?.map_err(Error::from)?;
assert_eq!(decoded.class(), message.class());
assert_eq!(decoded.method(), message.method());
assert_eq!(decoded.transaction_id(), message.transaction_id());
assert!(decoded.attributes().eq(message.attributes()));
```


References
----------

- [RFC 5245 - Interactive Connectivity Establishment (ICE)][RFC 5245]
- [RFC 5389 - Session Traversal Utilities for NAT (STUN)][RFC 5389]
- [RFC 5769 - Test Vectors for Session Traversal Utilities for NAT (STUN)][RFC 5769]
- [RFC 5780 - NAT Behavior Discovery Using Session Traversal Utilities for NAT][RFC 5780]
- [RFC 8016 - Mobility with Traversal Using Relays around NAT (TURN)][RFC 8016]
- [RFC 8656 - Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)][RFC 8656]

[RFC 5245]: https://tools.ietf.org/html/rfc5245
[RFC 5389]: https://tools.ietf.org/html/rfc5389
[RFC 5769]: https://tools.ietf.org/html/rfc5769
[RFC 5780]: https://tools.ietf.org/html/rfc5780
[RFC 8016]: https://tools.ietf.org/html/rfc8016
[RFC 8656]: https://tools.ietf.org/html/rfc8656
