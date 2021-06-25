// Bitcoin Hashes Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # SHA256d

use core::str;

use sha256;
use Hash as HashTrait;
use Error;

/// Output of the SHA256d hash function
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct Hash(
    #[cfg_attr(feature = "schemars", schemars(schema_with="crate::util::json_hex_string::len_32"))]
    [u8; 32]
);

hex_fmt_impl!(Debug, Hash);
hex_fmt_impl!(Display, Hash);
hex_fmt_impl!(LowerHex, Hash);
index_impl!(Hash);
serde_impl!(Hash, 32);
borrow_slice_impl!(Hash);

impl str::FromStr for Hash {
    type Err = ::hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ::hex::FromHex::from_hex(s)
    }
}

impl HashTrait for Hash {
    type Engine = sha256::HashEngine;
    type Inner = [u8; 32];

    fn engine() -> sha256::HashEngine {
        sha256::Hash::engine()
    }

    fn from_engine(e: sha256::HashEngine) -> Hash {
        let sha2 = sha256::Hash::from_engine(e);
        let sha2d = sha256::Hash::hash(&sha2[..]);

        let mut ret = [0; 32];
        ret.copy_from_slice(&sha2d[..]);
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
    use sha256d;
    use hex::{FromHex, ToHex};
    use Hash;
    use HashEngine;

#[derive(Clone)]
    struct Test {
input: &'static str,
           output: Vec<u8>,
           output_str: &'static str,
    }

#[test]
    fn test() {
        let tests = vec![
            // Test vector copied out of rust-bitcoin
            Test {
                input: "",
                output: vec![
                    0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
                    0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
                    0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
                    0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
                ],
                output_str: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = sha256d::Hash::hash(&test.input.as_bytes());
            assert_eq!(hash, sha256d::Hash::from_hex(test.output_str).expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_hex(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha256d::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            let manual_hash = sha256d::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.into_inner()[..].as_ref(), test.output.as_slice());
        }
    }

    #[cfg(feature="serde")]
    #[test]
    fn sha256_serde() {
        use serde_test::{Configure, Token, assert_tokens};

        static HASH_BYTES: [u8; 32] = [
            0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
            0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97,
            0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2,
            0xb7, 0x65, 0x44, 0x8c, 0x86, 0x35, 0xfb, 0x6c,
        ];

        let hash = sha256d::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(&hash.readable(), &[Token::Str("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c")]);
    }
}

#[cfg(all(test, feature="unstable"))]
mod benches {
    use test::Bencher;

    use sha256d;
    use Hash;
    use HashEngine;

    #[bench]
    pub fn sha256d_10(bh: & mut Bencher) {
        let mut engine = sha256d::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter( || {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256d_1k(bh: & mut Bencher) {
        let mut engine = sha256d::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter( || {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256d_64k(bh: & mut Bencher) {
        let mut engine = sha256d::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter( || {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
