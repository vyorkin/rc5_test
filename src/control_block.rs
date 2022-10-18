//! RC5 parameters packaged together.
//!  
//! Control block is represented using `b + 4` bytes.
//!
//! * `v` - 1 byte (version number).
//! * `w` - 1 byte.
//! * `r` - 1 byte.
//! * `b` - 1 byte.
//! * `k` - `b` bytes.
//!  
//! Used by RC5 "key-management" schemes to manage and transmit
//! entire RC5 control blocks, containing all of the relevant parameters in
//! addition to the usual secret cryptographic key variable.

pub struct ControlBlock {
    /// Version.
    pub v: u8,
    /// Word length.
    pub w: u8,
    /// Number of rounds.
    pub r: u8,
    /// Number of bytes in the secret key.
    pub b: u8,
    /// Secret key.
    pub k: Vec<u8>,
}

impl ControlBlock {
    /// Creates a control block with a nominal choice of parameters.
    pub fn nominal(key: Vec<u8>) -> Self {
        Self {
            v: 0x10,
            w: 32,
            r: 16,
            b: key.len() as u8,
            k: key,
        }
    }
}
