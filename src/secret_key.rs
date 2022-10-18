//! A variable-length cryptographic key.

use crate::{Error, Word};
use rand::{thread_rng, RngCore};
use secrecy::{ExposeSecret, SecretVec};

/// A variable-legnth cryptographic key.
///
/// Limits accidental exposure and ensures it is wiped rom
/// memory when dropped by securely zeroing memory using
/// techniques which guarantee they won't be "optimized away" by the compiler.
///
/// See: [memory zeroization](https://en.wikipedia.org/wiki/Zeroisation),
/// [secrecy crate docs](https://docs.rs/secrecy/latest/secrecy/),
/// [zeroize crate docs](https://docs.rs/zeroize/latest/zeroize/)
pub struct SecretKey(SecretVec<u8>);

impl SecretKey {
    /// Maximum key length is 256
    /// according to the RC5 original paper.
    const MAX_KEY_LENGTH: usize = 256;

    /// Creates a new secret key from the given vector of bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() > Self::MAX_KEY_LENGTH {
            Err(Error::InvalidSecretKeyLength(bytes.len()))
        } else {
            Ok(Self(bytes.into()))
        }
    }

    /// Generates a random secret key of the given length.
    pub fn random(len: usize) -> Self {
        let mut data = vec![0u8; len];
        thread_rng().fill_bytes(&mut data);
        Self(data.into())
    }

    /// Length of the secret key in bytes.
    pub fn len(&self) -> usize {
        self.secret().len()
    }

    /// Returns a reference to a vector of the secret key's bytes.
    fn secret(&self) -> &Vec<u8> {
        self.0.expose_secret()
    }

    /// Converts the secret key into an vector of words.
    pub fn to_words<W: Word>(&self) -> Vec<W> {
        // According to 4.3 of the original RC5 paper:
        //
        // L[0..c-1] = K[0..b-1]
        //
        // where
        // L                 - Vector of words
        // c = max(b, 1) / u - Number of words in the vector L
        // u = w / 8         - Number of bytes in word, we use `W::BYTES` for this

        // In case of an empty secret key (when `self.len() == 0`),
        // we return a vector of words of length one with a single `W::zero()` element
        let len = self.len().max(1) / W::BYTES;
        let mut words = vec![W::zero(); len];

        // To convert secret key's bytes into vector of words
        //
        // for i = b - 1 downto 0 do
        //     L[i / u] = (L[i / u] <<< 8) + K[i]
        //
        // where
        // X + Y   - two's complement (modulo 2) addition of words X and Y
        // X <<< Y - cyclic/wrapping rotation of word X by Y bits
        // K       - Bytes of the secret key
        // L       - Vector of words (of size W::BYTES)
        //
        for i in (0..self.len()).rev() {
            let j = i / W::BYTES;

            // Convert key byte into a word.
            // Note, that we will never have `Word` implementations for
            // types smaller than `u16`, so it is ok to use `expect` here.
            let w = W::from(self.secret()[i]).expect("word should be larger than u8");

            // Here we use a regular `rotate_left` function instead of our
            // custom `rotate_left_by` becase we 8 is a constant number less than
            // the size of the smallest word: 8 < 16. Hence this is safe.
            let v = words[j].rotate_left(8).wrapping_add(&w);

            words[j] = v;
        }

        words
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_words() {
        let key1_bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let key1 = SecretKey::new(key1_bytes).unwrap();
        let key1_words = key1.to_words::<u16>();

        assert_eq!(
            key1_words,
            vec![256, 770, 1284, 1798, 2312, 2826, 3340, 3854]
        )
    }
}
