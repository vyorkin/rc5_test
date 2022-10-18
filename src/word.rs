//! Provides the `Word` trait and its implementations for `u16`, `u32` and `u64`.
//!
//! The RC5 is adaptable for processors of different word-lengths.
//! Hence all of the basic computational operations have `w`-bit words as inputs and outputs.
//! It is well-defined for any `w > 0`, but for simplicity only allowable
//! sizes are 16, 32 and 64. The nominal choice for `w` is 32 bits.

use num_traits::{PrimInt, WrappingAdd, WrappingSub, Zero};

use crate::{FromLeBytes, HasPQ, ToLeBytes};

/// A trait for types that can represent a word in RC5.
///
/// Our word type is a primitive integer (`PrimInt`),
/// has wrapping (modulo 2) addition and subtraction operations (`WrappingAdd` and `WrappingSub`),
/// magic constants (`HasPQ`) and is convertible to/from little-endian byte array (`FromLeBytes` and `ToLeBytes`).
///
/// According to section *3. Notation and RC5 Primitive Operations* of the [original paper](https://www.grc.com/r&d/rc5.pdf):
///
/// In `rotate_right_by` and `rotate_left_by` functions, `n` is
/// interpreted modulo `w` (size of the word in bits), so that when `w` is a power of two,
/// only the `lg(w)` low-order bits are used to determine the rotation amount.
pub trait Word:
    PrimInt + Zero + WrappingAdd + WrappingSub + HasPQ + FromLeBytes + ToLeBytes
{
    /// The size of this word type in bits
    const BITS: usize;

    /// The size of this word type in bytes
    const BYTES: usize = Self::BITS / u8::BITS as usize;

    /// The default reasonable number of rounds.
    const ROUNDS: usize;

    /// Shifts the bits to the left by a specified `n` word,
    /// wrapping the truncated bits to the end of the resulting word.
    ///
    /// Corresponds to `<<<` operator from the RC5 paper.
    fn rotate_left_by(&self, n: Self) -> Self {
        self.rotate_left(n.to_u32().unwrap() % Self::BITS as u32)
    }

    /// Shifts the bits to the right by a specified `word`, wrapping
    /// the truncated bits to the end of the resulting word.
    ///
    /// Corresponds to `>>>` operator from the RC5 paper.
    fn rotate_right_by(&self, n: Self) -> Self {
        self.rotate_right(n.to_u32().unwrap() % Self::BITS as u32)
    }
}

/// Implements the `Word` trait for a given unsigned integer type.
macro_rules! word_impl {
    ($t:ty, $r:literal) => {
        impl Word for $t {
            const BITS: usize = Self::BITS as usize;
            const ROUNDS: usize = $r;
        }
    };
}

// Here is the table that might help
// you to choose a reasonable number of rounds:
//
// |  w  |  r  |
// |-----|-----|
// |   8 |   8 |
// |  16 |  12 |
// |  32 |  16 |
// |  64 |  20 |
// | 128 |  24 |
// | 256 |  28 |

// The original RC5 publication suggested using 12 rounds
// when `w=32` and 16 rounds when `w=64`. In response to cryptanalysis,
// the authors changed the recommendation when `w=32` to 16 rounds (see [RC5sec](https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#ref-RC5sec)).
// So the recommended/nominal choice of parameters is RC5-32/16/16.

word_impl!(u16, 12); // RC5-16/12/b
word_impl!(u32, 16); // RC5-32/16/b
word_impl!(u64, 20); // RC5-64/20/b

#[cfg(test)]
mod tests {
    use super::*;

    // Sanity check tests

    #[test]
    fn u16_sizes() {
        assert_eq!(<u16 as Word>::BITS, 16);
        assert_eq!(<u16 as Word>::BYTES, 2);
    }

    #[test]
    fn u32_sizes() {
        assert_eq!(<u32 as Word>::BITS, 32);
        assert_eq!(<u32 as Word>::BYTES, 4);
    }

    #[test]
    fn u64_sizes() {
        assert_eq!(<u64 as Word>::BITS, 64);
        assert_eq!(<u64 as Word>::BYTES, 8);
    }

    #[test]
    fn rotate_left_by() {
        let n = 0x0123456789ABCDEFu64;
        let m = 0x3456789ABCDEF012u64;
        let bits: u64 = 12 + 64 * 1_000_000;
        let r = Word::rotate_left_by(&n, bits);
        assert_eq!(r, m);
    }

    #[test]
    fn rotate_right_by() {
        let n = 0x0123456789ABCDEFu64;
        let m = 0xDEF0123456789ABCu64;
        let bits = 12 + 64 * 100_000;
        let r = Word::rotate_right_by(&n, bits);
        assert_eq!(r, m);
    }
}
