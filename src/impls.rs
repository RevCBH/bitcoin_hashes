// Bitcoin Hashes Library
// Written in 2019 by
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

//! `std` / `core2` Impls
//!
//! impls of traits defined in `std` / `core2` and not in `core`

#[cfg(feature = "std")]
use std::{error, io};

#[cfg(not(feature = "std"))]
use core2::{error, io};

use {hex, sha1, sha256, sha512, ripemd160, siphash24, blake2b};
use HashEngine;
use Error;

use crate::blake2b160;

impl error::Error for Error {
    #[cfg(feature = "std")]
    fn cause(&self) -> Option<&error::Error> { None }
    #[cfg(feature = "std")]
    fn description(&self) -> &str { "`std::error::description` is deprecated" }
}

impl error::Error for hex::Error {
    #[cfg(feature = "std")]
    fn cause(&self) -> Option<&error::Error> { None }
    #[cfg(feature = "std")]
    fn description(&self) -> &str { "`std::error::description` is deprecated" }
}

impl io::Write for sha1::HashEngine {
    fn flush(&mut self) -> io::Result<()> { Ok(()) }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }
}

impl io::Write for sha256::HashEngine {
    fn flush(&mut self) -> io::Result<()> { Ok(()) }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }
}

impl io::Write for sha512::HashEngine {
    fn flush(&mut self) -> io::Result<()> { Ok(()) }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }
}

impl io::Write for ripemd160::HashEngine {
    fn flush(&mut self) -> io::Result<()> { Ok(()) }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }
}

impl io::Write for siphash24::HashEngine {
    fn flush(&mut self) -> io::Result<()> { Ok(()) }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }
}

impl io::Write for blake2b::HashEngine {
    fn flush(&mut self) -> io::Result<()> { Ok(()) }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }
}

impl io::Write for blake2b160::HashEngine {
    fn flush(&mut self) -> io::Result<()> { Ok(()) }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input(buf);
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::io::Write;

    use {sha1, sha256, sha256d, sha512, ripemd160, hash160, siphash24, blake2b};
    use Hash;

    macro_rules! write_test {
        ($mod:ident, $exp_empty:expr, $exp_256:expr, $exp_64k:expr,) => {
            #[test]
            fn $mod() {
                let mut engine = $mod::Hash::engine();
                engine.write_all(&[]).unwrap();
                assert_eq!(
                    format!("{}", $mod::Hash::from_engine(engine)),
                    $exp_empty
                );

                let mut engine = $mod::Hash::engine();
                engine.write_all(&[1; 256]).unwrap();
                assert_eq!(
                    format!("{}", $mod::Hash::from_engine(engine)),
                    $exp_256
                );

                let mut engine = $mod::Hash::engine();
                engine.write_all(&[99; 64000]).unwrap();
                assert_eq!(
                    format!("{}", $mod::Hash::from_engine(engine)),
                    $exp_64k
                );
            }
        }
    }

    write_test!(
        sha1,
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "ac458b067c6b021c7e9358229b636e9d1e4cb154",
        "e4b66838f9f7b6f91e5be32a02ae78094df402e7",
    );

    write_test!(
        sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "2661920f2409dd6c8adeb0c44972959f232b6429afa913845d0fd95e7e768234",
        "5c5e904f5d4fd587c7a906bf846e08a927286f388c54c39213a4884695271bbc",
    );

    write_test!(
        sha256d,
        "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        "64af0bc2284cf292b03f0e30bdef300f9252763a497e41d9105dc730d8004037",
        "0733f0c3dc370b3752de1fa29b5dd94c61f45bad3f64a07c43a0d78a14d45000",
    );

    write_test!(
        sha512,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "57ecf739d3a7ca647639adae80a05f4f361304bfcbfa1ceba93296b096e74287\
         45fc10c142cecdd3bb587a3dba598c072f6f78b31cc0a06a3da0105ee51f75d6",
        "dd28f78c53f3bc9bd0c2dca9642a1ad402a70412f985c1f6e54fadb98ce9c458\
         4761df8d04ed04bb734ba48dd2106bb9ea54524f1394cdd18e6da3166e71c3ee",
    );

    write_test!(
        ripemd160,
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "e571a1ca5b780aa52bafdb9ec852544ffca418ba",
        "ddd2ecce739e823629c7d46ab18918e9c4a51c75",
    );

    write_test!(
        hash160,
        "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        "671356a1a874695ad3bc20cae440f4360835bd5a",
        "a9608c952c8dbcc20c53803d2ca5ad31d64d9313",
    );

    write_test!(
        siphash24,
        "d70077739d4b921e",
        "3a3ccefde9b5b1e3",
        "ce456e4e4ecbc5bf",
    );

    write_test!(
        blake2b,
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        "feb016c28375e7a92909827ab94ef89d0e8c8bd6d989054d4d5f0c2048c6ec47",
        "04377ffc3310d8fa07fcbcb9c51c359d52645aa827e5749cd1d32598c7cf1eb2",
    );
}
