// Handshake Hashes Library
// Written in 2021 by
//   Bennett Hoffman <benn.hoffman@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # blake2b

use core::str;

use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;
use hex;
use Error;
use Hash as HashTrait;
use HashEngine as EngineTrait;

const BLOCK_SIZE: usize = 64;

/// Output of the blake2b hash function
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct Hash(
    #[cfg_attr(
        feature = "schemars",
        schemars(schema_with = "crate::util::json_hex_string::len_32")
    )]
    [u8; 32],
);

impl str::FromStr for Hash {
    type Err = ::hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ::hex::FromHex::from_hex(s)
    }
}

hex_fmt_impl!(Debug, Hash);
hex_fmt_impl!(Display, Hash);
hex_fmt_impl!(LowerHex, Hash);
index_impl!(Hash);
serde_impl!(Hash, 32);
borrow_slice_impl!(Hash);

/// Output of the blake2b hash function
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Midstate(pub [u8; 32]);

hex_fmt_impl!(Debug, Midstate);
hex_fmt_impl!(Display, Midstate);
hex_fmt_impl!(LowerHex, Midstate);
index_impl!(Midstate);
serde_impl!(Midstate, 32);
borrow_slice_impl!(Midstate);

impl str::FromStr for Midstate {
    type Err = ::hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ::hex::FromHex::from_hex(s)
    }
}

impl Midstate {
    /// Length of the midstate, in bytes.
    const LEN: usize = 32;

    /// Flag indicating whether user-visible serializations of this hash
    /// should be backward, like in bitcoin.
    const DISPLAY_BACKWARD: bool = false;

    /// Construct a new midstate from the inner value.
    pub fn from_inner(inner: [u8; 32]) -> Self {
        Midstate(inner)
    }

    /// Copies a byte slice into the [Midstate] object.
    pub fn from_slice(sl: &[u8]) -> Result<Midstate, Error> {
        if sl.len() != Self::LEN {
            Err(Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Midstate(ret))
        }
    }

    /// Unwraps the [Midstate] and returns the underlying byte array.
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl hex::FromHex for Midstate {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where
        I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        // DISPLAY_BACKWARD is false
        Ok(Midstate::from_inner(hex::FromHex::from_byte_iter(
            iter.rev(),
        )?))
    }
}

/// Engine to compute the blake2b hash function
#[derive(Clone)]
pub struct HashEngine {
    buffer: [u8; BLOCK_SIZE],
    blake: VarBlake2b,
    length: usize,
}

impl Default for HashEngine {
    fn default() -> Self {
        HashEngine {
            buffer: [0; BLOCK_SIZE],
            blake: VarBlake2b::new(32).unwrap(),
            length: 0,
        }
    }
}

impl EngineTrait for HashEngine {
    type MidState = Midstate;

    fn input(&mut self, data: &[u8]) {
        self.blake.update(data);
    }

    // #[cfg(not(fuzzing))]
    // fn midstate(&self) -> Midstate {
    //     let mut ret = [0; 32];
    //     for (val, ret_bytes) in self.h.iter().zip(ret.chunks_mut(4)) {
    //         ret_bytes.copy_from_slice(&util::u32_to_array_be(*val));
    //     }
    //     Midstate(ret)
    // }

    // #[cfg(fuzzing)]
    fn midstate(&self) -> Midstate {
        let mut ret = [0; 32];
        ret.copy_from_slice(&self.buffer[..32]);
        Midstate(ret)
    }

    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> usize {
        self.length
    }
}

impl HashTrait for Hash {
    type Engine = HashEngine;
    type Inner = [u8; 32];

    fn engine() -> HashEngine {
        Default::default()
    }

    fn from_engine(mut e: HashEngine) -> Hash {
        let mut ret = [0; 32];
        e.blake.finalize_variable_reset(|res| {
            ret.copy_from_slice(res);
        });

        Hash(ret)
    }

    const LEN: usize = 32;

    fn from_slice(sl: &[u8]) -> Result<Hash, Error> {
        if sl.len() != 32 {
            Err(Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Hash(ret))
        }
    }

    const DISPLAY_BACKWARD: bool = false;

    fn into_inner(self) -> Self::Inner {
        self.0
    }

    fn as_inner(&self) -> &Self::Inner {
        &self.0
    }

    fn from_inner(inner: Self::Inner) -> Self {
        Hash(inner)
    }
}

#[cfg(test)]
mod tests {
    use blake2::digest::{Update, VariableOutput};
    use blake2::VarBlake2b;
    use blake2b;
    use hex::{FromHex, ToHex};
    use Hash;

    #[test]
    fn test() {
        let input = "The quick brown fox jumps over the lazy dog";
        let output_str = "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9";

        let mut raw_blake = VarBlake2b::new(32).unwrap();
        raw_blake.update(input);
        raw_blake.finalize_variable_reset(|res| {
            assert_eq!(&res.to_hex(), &output_str);
        });

        let hash = blake2b::Hash::hash(&input.as_bytes());
        assert_eq!(hash, blake2b::Hash::from_hex(output_str).expect("parse hex"));
        assert_eq!(&hash.to_hex(), &output_str);
    }
}
