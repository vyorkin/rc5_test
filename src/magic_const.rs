//! Abstraction to deal with `P` and `Q` magic constants.
//!
//! The key-expansion algorithm uses two word-sized
//! binary constants `P` and `Q`. They are defined for abitrary word
//! according to *4.3* of the [original RC5 paper](https://www.grc.com/r&d/rc5.pdf).

/// A trait for types that have `P` and `Q` magic constants.
pub trait HasPQ {
    fn p() -> Self;
    fn q() -> Self;
}

// There is an algorithm to compute P and Q constants for arbitrary word-size `w`,
// but already precomputed values for w = 16, 32 and 64 are suitable for our purposes.
//
// We can implement this algorithm later if we need to use word sizes larger than 64 bits.

// Another approach would be to have a static `HashMap` and
// initialize it using the `lazy_static!` macro.

/// Implements the `ToLeBytes` trait for a given type.
macro_rules! has_pq_impl {
    ($t:ty, $p:literal, $q:literal) => {
        impl HasPQ for $t {
            #[inline]
            fn p() -> Self {
                $p
            }

            #[inline]
            fn q() -> Self {
                $q
            }
        }
    };
}

has_pq_impl!(u16, 0xb7e1, 0x9e37);
has_pq_impl!(u32, 0xb7e15163, 0x9e3779b9);
has_pq_impl!(u64, 0xb7e151628aed2a6b, 0x9e3779b97f4a7c15);
