use crate::{Error, SecretKey, Word};

/// Expanded key table.
///
/// The key-expansion algorithm has a certain amount of "one-wayness":
/// it is not so easy to determine the secret key from expanded key table.
/// Hence we're not using [secrecy](https://docs.rs/secrecy/latest/secrecy/) here.
#[derive(Debug, PartialEq, Eq)]
pub struct ExpandedKeyTable<W>(pub(crate) Vec<W>);

impl<W: Word> ExpandedKeyTable<W> {
    /// Maximum number of rounds
    /// according to the RC5 original paper.
    const MAX_NUMBER_OF_ROUNDS: usize = 256;

    /// Creates an expanded key table.
    ///
    /// The key-expansion routine expands the users secret key to fill the
    /// expanded key vector of random binary words determined by key.
    ///
    /// The algorithm uses two "magic constants" `P` and `Q`
    /// (see the `HasPQ`'s trait implementations for `u8`, `u16`, `u32` and `u64`)
    /// and consists of three simple algorithmic parts:
    /// 1. Converting the secret key from bytes to words (see `SecretKey::to_words`).
    /// 2. Initializing the vector S (expanded key table).
    /// 3. Mixing in the secret key.
    pub fn new(key: &SecretKey, number_of_rounds: usize) -> Result<Self, Error> {
        if number_of_rounds > Self::MAX_NUMBER_OF_ROUNDS {
            return Err(Error::InvalidNumberOfRounds(number_of_rounds));
        }

        // Create and initialize a key table.
        // Expanded key table resembles a vector of t = 2 * (r + 1) random binary words.
        let mut key_table = Self::setup(2 * (number_of_rounds + 1));
        // Mixin the user's secret key.
        Self::mixin(&mut key_table, key.to_words());

        Ok(Self(key_table))
    }

    /// Creates a key table initialized to a particular fixed (key-independent)
    /// pseudo-random bit pattern, using an arithmetic progression
    /// modulo `2^w` determined by magic constants `P` and `Q`.
    fn setup(len: usize) -> Vec<W> {
        // Pseudo-code:
        //
        // S[0] = P
        // for i = 1 to t - 1 do
        //     S[i] = S[i - 1] + Q
        //
        // where
        //
        // S - Key-expansion table

        let mut key_table = vec![W::zero(); len];

        key_table[0] = W::p();
        for i in 1..key_table.len() {
            key_table[i] = key_table[i - 1].wrapping_add(&W::q());
        }

        key_table
    }

    /// Mixins the user's secret key in 3 passes over a
    /// key table vector and a vector of key words.
    fn mixin(key_table: &mut Vec<W>, key_words: Vec<W>) {
        // Pseudo-code:
        //
        // i = j = 0
        // A = B = 0
        // do 3 * max(t, c) times:
        //    A = S[i] = (S[i] + A + B) <<< 3
        //    B = L[j] = (L[j] + A + B) <<< (A + B)
        //    i = (i + 1) mod t
        //    j = (j + 1) mod c
        //
        // where
        //
        // X + Y   - Two's complement (modulo 2) addition of words X and Y
        // X <<< Y - Cyclic/wrapping rotation of word X by Y bits
        //
        // S = table - Key-expansion table
        // L = key_words - Secret key words
        // t = table.len() - Length of the key-expansion table
        // c = key_words.len() - Length of the key words vector

        let mut key_words = key_words;

        let (mut a, mut b) = (W::zero(), W::zero());
        let (mut i, mut j) = (0, 0);

        let mix_steps = key_table.len().max(key_words.len()); // max(t, c)

        for _ in 0..(3 * mix_steps) {
            // Note that we use the `rotate_left` function here instead of
            // our custom `rotate_left_by` (<<<). It is safe because we known that 3 is
            // less than the size of the smallest word (u16): 3 < 16.

            key_table[i] = key_table[i]
                .wrapping_add(&a)
                .wrapping_add(&b)
                .rotate_left(3);
            a = key_table[i];

            // And here we use the `rotate_left_by`, because the sum of
            // `a + b` can be greater than 64 (the size of `u64`).

            key_words[j] = key_words[j]
                .wrapping_add(&a)
                .wrapping_add(&b)
                .rotate_left_by(a.wrapping_add(&b));
            b = key_words[j];

            i = (i + 1) % key_table.len();
            j = (j + 1) % key_words.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let key1_bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let key1 = SecretKey::new(key1_bytes).unwrap();
        let key1_table = ExpandedKeyTable::<u16>::new(&key1, 12).unwrap();
        assert_eq!(
            key1_table,
            ExpandedKeyTable(vec![
                35335, 28312, 22618, 34867, 45234, 46162, 22833, 59388, 47522, 35862, 3067, 9299,
                32031, 62182, 903, 8243, 57179, 45493, 29169, 52645, 27594, 36810, 63883, 25203,
                40548, 8227
            ])
        );
    }
}
