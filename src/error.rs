use thiserror::Error;

/// RC5 errors.
#[derive(Error, Debug)]
pub enum Error {
    /// Length of the secret key is greater than 256.
    #[error("Invalid secret key length: `{0}`")]
    InvalidSecretKeyLength(usize),

    /// Number of rounds is greater than 256.
    #[error("Invalid number of rounds: `{0}`")]
    InvalidNumberOfRounds(usize),
}
