use num::U12;

pub mod attributes;
pub mod errors;
pub mod methods;

/// Method set that are defined in [RFC 5389].
///
/// [RFC 5389]: https://tools.ietf.org/html/rfc5389
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// See [Binding].
    ///
    /// [Binding]: ./methods/struct.Binding.html
    Binding,
}
impl ::Method for Method {
    fn from_u12(value: U12) -> Option<Self> {
        match value.as_u16() {
            methods::Binding::CODEPOINT => Some(Method::Binding),
            _ => None,
        }
    }

    fn as_u12(&self) -> U12 {
        match *self {
            Method::Binding => methods::Binding.as_u12(),
        }
    }
}
impl From<methods::Binding> for Method {
    fn from(_: methods::Binding) -> Self {
        Method::Binding
    }
}
