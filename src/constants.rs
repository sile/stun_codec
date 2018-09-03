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
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
