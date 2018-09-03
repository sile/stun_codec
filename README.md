stun_codec
===========
[![stun_codec](http://meritbadge.herokuapp.com/stun_codec)](https://crates.io/crates/stun_codec)
[![Documentation](https://docs.rs/stun_codec/badge.svg)](https://docs.rs/stun_codec)
[![Build Status](https://travis-ci.org/sile/stun_codec.svg?branch=master)](https://travis-ci.org/sile/stun_codec)
[![Code Coverage](https://codecov.io/gh/sile/stun_codec/branch/master/graph/badge.svg)](https://codecov.io/gh/sile/stun_codec/branch/master)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Encoders and decoders for [STUN (RFC 5389)][RFC 5389].

[Documentation](https://docs.rs/stun_codec)


Examples
--------

```rust
use bytecodec::{DecodeExt, EncodeExt};
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};
use stun_codec::rfc5389::{attributes::Software, Attribute, Method};

// Creates a message
let mut message = Message::new(
    MessageClass::Request,
    Method::Binding,
    TransactionId::new([3; 12]),
);
message.push_attribute(Attribute::Software(Software::new("foo".to_owned())?));

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
let mut decoder = MessageDecoder::<Method, Attribute>::new();
let decoded = decoder.decode_from_bytes(&bytes)?;
assert_eq!(decoded.class(), message.class());
assert_eq!(decoded.method(), message.method());
assert_eq!(decoded.transaction_id(), message.transaction_id());
assert!(decoded.attributes().eq(message.attributes()));
```


References
----------

- [RFC 5389 - Session Traversal Utilities for NAT (STUN)][RFC 5389]
- [RFC 5769 - Test Vectors for Session Traversal Utilities for NAT (STUN)][RFC 5769]

[RFC 5389]: https://tools.ietf.org/html/rfc5389
[RFC 5769]: https://tools.ietf.org/html/rfc5769
