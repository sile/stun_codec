//! Methods that are defined in [RFC 5766 -- 13. New STUN Methods].
//!
//! [RFC 5766 -- 13. New STUN Methods]: https://tools.ietf.org/html/rfc5766#section-13
use crate::Method;

/// Allocate method.
///
/// Only request/response semantics defined.
pub const ALLOCATE: Method = Method(0x003);

/// Reference method.
///
/// Only request/response semantics defined.
pub const REFRESH: Method = Method(0x004);

/// Send method.
///
/// Only indication semantics defined.
pub const SEND: Method = Method(0x006);

/// Data method.
///
/// only indication semantics defined.
pub const DATA: Method = Method(0x007);

/// CreatePermission method.
///
/// Only request/response semantics defined.
pub const CREATE_PERMISSION: Method = Method(0x008);

/// ChannelBind method.
///
/// Only request/response semantics defined.
pub const CHANNEL_BIND: Method = Method(0x009);
