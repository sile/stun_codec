use bytecodec::{ErrorKind, Result};

/// STUN method.
///
/// > All STUN messages start with a fixed header that includes a **method**, a
/// > class, and the transaction ID.  The **method** indicates which of the
/// > various requests or indications this is;
/// >
/// > [RFC 5389 -- 3. Overview of Operation]
///
/// [RFC 5389 -- 3. Overview of Operation]: https://tools.ietf.org/html/rfc5389#section-3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Method(pub(crate) u16);
impl Method {
    /// Makes a new `Method` instance with the given codepoint.
    ///
    /// # Errors
    ///
    /// If `codepoint` is greater than `0xFFF`, this will return an `ErrorKind::InvalidInput` error.
    pub fn new(codepoint: u16) -> Result<Self> {
        track_assert!(codepoint < 0x1000, ErrorKind::InvalidInput; codepoint);
        Ok(Method(codepoint))
    }

    /// Returns the codepoint corresponding this method.
    pub fn as_u16(self) -> u16 {
        self.0
    }
}
impl From<u8> for Method {
    fn from(f: u8) -> Self {
        Method(u16::from(f))
    }
}
