//! Provides little-endian from/to bytes conversion.
//!
//! RC5 uses standart little-endian conventions for packing bytes into
//! input/output blocks, accroding to *4. The RC5 Algorithm* of [the original paper](https://www.grc.com/r&d/rc5.pdf).
//!
//! There are `from_le_bytes` and `to_le_bytes` conversion functions defined for
//! primitive integer types like `u16`, `u32` and `u64`, but there are no abstractions.
//! This module defines two traits `FromLeBytes` and `ToLeBytes` that let us to
//! abstract away from concrete integer types.

use std::convert::{TryFrom, TryInto};

/// Used to convert byte arrays in little-endian
/// byte order to integer values.
pub trait FromLeBytes {
    type T: TryFrom<Vec<u8>>;

    /// Create a native endian integer value from
    /// its representation as a byte array in little endian.
    fn from_le_bytes(bytes: Self::T) -> Self;
}

/// Used to convert integer values to
/// byte arrays in little-endian byte order.
pub trait ToLeBytes {
    type T: TryInto<Vec<u8>>;

    /// Returns the memory representation of this integer as
    /// a byte array in little-endian byte order.
    fn to_le_bytes(&self) -> Self::T;
}

/// Implements the `FromLeBytes` trait for a given type.
macro_rules! from_le_bytes_impl {
    ($t:ty) => {
        impl FromLeBytes for $t {
            type T = [u8; Self::BITS as usize / 8];

            fn from_le_bytes(bytes: Self::T) -> Self {
                Self::from_le_bytes(bytes)
            }
        }
    };
}

/// Implements the `ToLeBytes` trait for a given type.
macro_rules! to_le_bytes_impl {
    ($t:ty) => {
        impl ToLeBytes for $t {
            type T = [u8; Self::BITS as usize / 8];

            fn to_le_bytes(&self) -> Self::T {
                Self::to_le_bytes(*self)
            }
        }
    };
}

from_le_bytes_impl!(u16);
from_le_bytes_impl!(u32);
from_le_bytes_impl!(u64);

to_le_bytes_impl!(u16);
to_le_bytes_impl!(u32);
to_le_bytes_impl!(u64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_le_bytes() {
        assert_eq!(<u16 as FromLeBytes>::from_le_bytes([24, 48]), 12312u16);
        assert_eq!(
            <u32 as FromLeBytes>::from_le_bytes([179, 181, 86, 7]),
            123123123u32
        );
        assert_eq!(
            <u64 as FromLeBytes>::from_le_bytes([179, 243, 99, 1, 212, 107, 181, 1]),
            123123123123123123u64
        );
    }

    #[test]
    fn to_le_bytes() {
        assert_eq!(ToLeBytes::to_le_bytes(&12312u16), [24, 48]);
        assert_eq!(ToLeBytes::to_le_bytes(&123123123u32), [179, 181, 86, 7]);
        assert_eq!(
            ToLeBytes::to_le_bytes(&123123123123123123u64),
            [179, 243, 99, 1, 212, 107, 181, 1]
        );
    }
}
