//! [RC5 encryption algorithm](https://www.grc.com/r&d/rc5.pdf) implementation.
//!
//! RC5 is a symmetric block cipher.
//! The same secret cryptographic key is used for ecryption and
//! for decryption.
//!
//! There are several distinct "RC5" algorithms, depending on the
//! choice of parameters `w` and `r`:
//!
//! * `w` - Word size, in bits.
//!         Allowable sizes are 16, 32 and 64.
//!         Nominal size is 32 bits.
//! * `r` - Number of rounds from 0 to 255.
//!         Choosing larger number of rounds provides an
//!         increased level of security.
//!
//! Notational convention: RC5-w/r/b, where `b` is the length of a secret key.

pub mod rc5;
pub use rc5::RC5;

pub mod block;
use block::Block;

pub mod control_block;
pub use control_block::ControlBlock;

pub mod error;
pub use error::Error;

pub mod le_bytes;
use le_bytes::{FromLeBytes, ToLeBytes};

pub mod magic_const;
use magic_const::HasPQ;

pub mod word;
pub use word::Word;

pub mod secret_key;
pub use secret_key::SecretKey;

pub mod expanded_key_table;
use expanded_key_table::ExpandedKeyTable;
