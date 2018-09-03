use num::U12;

/// STUN method.
///
/// > All STUN messages start with a fixed header that includes a **method**, a
/// > class, and the transaction ID.  The **method** indicates which of the
/// > various requests or indications this is;
/// >
/// > [RFC 5389 -- 3. Overview of Operation]
///
/// [RFC 5389 -- 3. Overview of Operation]: https://tools.ietf.org/html/rfc5389#section-3
pub trait Method: Sized + Clone {
    /// Tries to convert from `codepoint` to the corresponding method.
    ///
    /// If no such method exists, this will return `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stun_codec::Method;
    /// use stun_codec::num::U12;
    /// use stun_codec::rfc5389::methods::Binding;
    ///
    /// assert!(Binding::from_u12(U12::from_u8(1)).is_some());
    /// assert!(Binding::from_u12(U12::from_u8(0)).is_none());
    /// ```
    fn from_u12(codepoint: U12) -> Option<Self>;

    /// Returns the codepoint corresponding this method.
    ///
    /// # Example
    ///
    /// ```
    /// use stun_codec::Method;
    /// use stun_codec::rfc5389::methods::Binding;
    ///
    /// assert_eq!(Binding.as_u12().as_u16(), 1);
    /// ```
    fn as_u12(&self) -> U12;
}
