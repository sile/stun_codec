//! Miscellaneous types.

/// Unsigned 12 bit integer.
#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct U12(u16);
impl U12 {
    /// Converts from `u8` value.
    pub fn from_u8(value: u8) -> Self {
        U12(value as u16)
    }

    /// Tries to convert from `u16` value.
    ///
    /// If `value` is greater than `0xFFF`, this will return `None`.
    pub fn from_u16(value: u16) -> Option<Self> {
        if value < 0x1000 {
            Some(U12(value))
        } else {
            None
        }
    }

    /// Converts to `u16` value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}
