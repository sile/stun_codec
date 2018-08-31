/// Transaction ID.
///
/// > STUN is a client-server protocol.  It supports two types of
/// > transactions.  One is a request/response transaction in which a
/// > client sends a request to a server, and the server returns a
/// > response.  The second is an indication transaction in which either
/// > agent -- client or server -- sends an indication that generates no
/// > response.  Both types of transactions include a **transaction ID**, which
/// > is a randomly selected 96-bit number.  For request/response
/// > transactions, this transaction ID allows the client to associate the
/// > response with the request that generated it; for indications, the
/// > transaction ID serves as a debugging aid.
/// >
/// > ([RFC 5389 -- 3. Overview of Operation](https://tools.ietf.org/html/rfc5389#section-3))
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransactionId([u8; 12]);
impl TransactionId {
    /// Makes a new `TransactionId` instance.
    pub fn new(id: [u8; 12]) -> Self {
        TransactionId(id)
    }

    /// Returns a reference to the bytes that represents the identifier.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}
impl AsRef<[u8]> for TransactionId {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
