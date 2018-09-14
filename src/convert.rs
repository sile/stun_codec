//! Conversion traits.

/// This trait allows for attempting to a cheap reference-to-reference conversion.
pub trait TryAsRef<T> {
    /// Attempts to convert `self` to a reference to `T`.
    ///
    /// If it is not possible, this method will return `None`.
    fn try_as_ref(&self) -> Option<&T>;
}
