//! Polymorphic implementation of the RC5 algorithm.
//!
//! RC5 is iterative in stucture, with a variable number of rounds.
//! By specifying a number of rounds user can explicitly
//! manipulate the tradeoff between higher speed and higher security.
//!
//! For example:
//!
//! * `0` - No encryption.
//! * `1` - Easily broken.
//! * `6` - Provides "some" security.
//! * `>= 32` - Might be appropriate for applications where
//!    security is the primary concern and speed is.
//!    relatively unimportant.

use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
};

use crate::{Block, Error, ExpandedKeyTable, FromLeBytes, SecretKey, ToLeBytes, Word};

/// An RC5 encryption algorithm instance.
pub struct RC5<W> {
    /// Expanded key vector of random binary words determined by the secret key.
    pub(crate) expanded_key_table: ExpandedKeyTable<W>,
    /// Number of rounds.
    pub(crate) number_of_rounds: usize,
}

impl<W> RC5<W>
where
    W: Word,
    <<W as FromLeBytes>::T as TryFrom<Vec<u8>>>::Error: Debug,
    <<W as ToLeBytes>::T as TryInto<Vec<u8>>>::Error: Debug,
{
    /// Creates a new RC5 instance for a given secret key with
    /// a default reasonable number of rounds.
    pub fn new(secret_key: Vec<u8>) -> Result<Self, Error> {
        Self::new_with_rounds(secret_key, W::ROUNDS)
    }

    /// Creates a new RC5 instance for a given secret key and a number of rounds.
    pub fn new_with_rounds(secret_key: Vec<u8>, number_of_rounds: usize) -> Result<Self, Error> {
        let secret_key = SecretKey::new(secret_key)?;

        // Setup an expanded key table that we're going to re-use for encryption/decryption.
        let expanded_key_table = ExpandedKeyTable::new(&secret_key, number_of_rounds)?;

        Ok(Self {
            expanded_key_table,
            number_of_rounds,
        })

        // Since we don't need to keep the secret key after creation of
        // the expanded key table, it is erased from memory
        // (by securely zeroing it) when the `secret_key` variable is dropped.
    }

    /// Encrypts plain text.
    pub fn encode(&self, plaintext: &[u8]) -> Vec<u8> {
        let blocks = bytes_to_blocks::<W>(plaintext)
            .iter()
            .map(|b| b.encode(&self))
            .collect::<Vec<_>>();
        blocks_to_bytes(&blocks)
    }

    /// Decrypts cipher text.
    pub fn decode(&self, ciphertext: &[u8]) -> Vec<u8> {
        let blocks = bytes_to_blocks::<W>(ciphertext)
            .iter()
            .map(|b| b.decode(&self))
            .collect::<Vec<_>>();
        blocks_to_bytes(&blocks)
    }
}

fn bytes_to_blocks<W: Word>(bytes: &[u8]) -> Vec<Block<W>>
where
    <<W as FromLeBytes>::T as TryFrom<Vec<u8>>>::Error: Debug,
{
    bytes_to_words(bytes)
        .chunks(2)
        .map(Block::from_words)
        .collect()
}

fn bytes_to_words<W: Word>(bytes: &[u8]) -> Vec<W>
where
    <<W as FromLeBytes>::T as TryFrom<Vec<u8>>>::Error: Debug,
{
    bytes
        .chunks(W::BYTES)
        .map(|chunk| W::from_le_bytes(chunk.to_vec().try_into().unwrap()))
        .collect()
}

fn blocks_to_words<W: Word>(blocks: &Vec<Block<W>>) -> Vec<W> {
    blocks.iter().flat_map(Block::to_words).collect()
}

fn blocks_to_bytes<W: Word>(blocks: &Vec<Block<W>>) -> Vec<u8>
where
    <<W as ToLeBytes>::T as TryInto<Vec<u8>>>::Error: Debug,
{
    blocks_to_words(blocks)
        .iter()
        .flat_map(|w| w.to_le_bytes().try_into().unwrap())
        .collect::<Vec<u8>>()
}
