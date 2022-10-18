use crate::{ExpandedKeyTable, Word, RC5};

// Block is a pair of words.
pub struct Block<W>(W, W);

impl<W: Word> Block<W> {
    /// Creates a new block from words `a` and `b`.
    pub fn new(a: W, b: W) -> Self {
        Self(a, b)
    }

    /// Crates a new block from a given slice of words.
    pub fn from_words(ws: &[W]) -> Self {
        Self::new(ws[0], ws[1])
    }

    /// Converts a block into a vector of words.
    pub fn to_words(&self) -> Vec<W> {
        vec![self.0, self.1]
    }

    /// Encrypts the block.
    pub fn encode(&self, ctx: &RC5<W>) -> Self {
        let RC5 {
            expanded_key_table: ExpandedKeyTable(key_table),
            number_of_rounds: r,
        } = ctx;

        // Pseudo-code:
        //
        // A = A + S[0]
        // B = B + S[1]
        // for i = 1 to r do
        //     A = ((A <+> B) <<< B) + S[2 * i]
        //     B = ((B <+> A) <<< A) + S[2 * i + 1]
        //
        // where
        //
        // X <<< Y - Cyclic/wrapping rotation of word X by Y bits
        // X <+> Y - Bitwise exclusive OR operation
        //
        // S       - Expanded key table
        // (A, B)  - Two `w`-bit registers
        // r       - Number of rounds

        let Block(mut a, mut b) = self;

        a = a.wrapping_add(&key_table[0]);
        b = b.wrapping_add(&key_table[1]);
        for i in 1..=*r {
            a = a
                .bitxor(b)
                .rotate_left_by(b)
                .wrapping_add(&key_table[2 * i]);
            b = b
                .bitxor(a)
                .rotate_left_by(a)
                .wrapping_add(&key_table[2 * i + 1]);
        }

        Block(a, b)
    }

    /// Decrypts the block.
    pub fn decode(&self, ctx: &RC5<W>) -> Self {
        let RC5 {
            expanded_key_table: ExpandedKeyTable(key_table),
            number_of_rounds: r,
        } = ctx;

        // Pseudo-code:
        //
        // for i = r downto 1 do
        //     B = ((B - S[2 * i + 1]) >>> A) <+> A
        //     A = ((A - S[2 * i]) >>> B) <+> B
        // B = B - S[1]
        // A = A - S[0]

        let Block(mut a, mut b) = self;

        for i in (1..=*r).rev() {
            b = b
                .wrapping_sub(&key_table[2 * i + 1])
                .rotate_right_by(a)
                .bitxor(a);
            a = a
                .wrapping_sub(&key_table[2 * i])
                .rotate_right_by(b)
                .bitxor(b);
        }
        b = b.wrapping_sub(&key_table[1]);
        a = a.wrapping_sub(&key_table[0]);

        Block(a, b)
    }
}
