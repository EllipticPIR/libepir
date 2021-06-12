use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;

/// The byte length of a scalar.
pub const SCALAR_SIZE: usize = 32;
/// The byte length of a point.
pub const POINT_SIZE : usize = 32;
/// The byte length of a ciphertext.
pub const CIPHER_SIZE: usize = 2 * POINT_SIZE;
/// log_2(DEFAULT_MMAX).
pub const DEFAULT_MMAX_MOD: u8 = 24;
/// The maximum number of entries in `mG.bin`.
pub const DEFAULT_MMAX: u32 = 1 << DEFAULT_MMAX_MOD;
/// The default data directory name.
pub const DEFAULT_DATA_DIR: &str = ".EllipticPIR";

/// The default path to mG.bin.
pub fn mg_default_path() -> Result<String, std::env::VarError> {
    Ok(std::env::var("HOME")? + "/" + DEFAULT_DATA_DIR + "/mG.bin")
}

pub mod ecelgamal;
pub mod selector;
pub mod reply;
pub mod wasm;

pub trait Rng {
    fn next(&mut self) -> Scalar;
}

#[derive(Default)]
pub struct DefaultRng {
    csprng: OsRng,
}

impl Rng for DefaultRng {
    fn next(&mut self) -> Scalar {
        Scalar::random(&mut self.csprng)
    }
}

pub struct ConstRng {
    scalars: Vec<Scalar>,
    index: usize,
}
impl ConstRng {
    pub fn new(scalars: Vec<Scalar>) -> Self {
        Self {
            scalars,
            index: 0,
        }
    }
}
impl Rng for ConstRng {
    fn next(&mut self) -> Scalar {
        self.index += 1;
        self.scalars[self.index - 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecelgamal::*;
    use sha2::{Digest, Sha256};
    pub const PRIVKEY: [u8; SCALAR_SIZE] = [
        0x7e, 0xf6, 0xad, 0xd2, 0xbe, 0xd5, 0x9a, 0x79,
        0xba, 0x6e, 0xdc, 0xfb, 0xa4, 0x8f, 0xde, 0x7a,
        0x55, 0x31, 0x75, 0x4a, 0xf5, 0x93, 0x76, 0x34,
        0x6c, 0x8b, 0x52, 0x84, 0xee, 0xf2, 0x52, 0x07,
    ];
    pub const PRIVKEY_STR: &str = "7ef6add2bed59a79ba6edcfba48fde7a5531754af59376346c8b5284eef25207";
    pub const PUBKEY: [u8; POINT_SIZE] = [
        0x9c, 0x76, 0x82, 0x3d, 0xbd, 0xb9, 0xbf, 0x04,
        0x8f, 0xc5, 0xc2, 0xaf, 0x00, 0x0e, 0x28, 0xa1,
        0x48, 0xee, 0x02, 0x19, 0x99, 0xfb, 0x7f, 0x21,
        0xca, 0x1f, 0x84, 0xb8, 0xfe, 0x73, 0xd7, 0xe8,
    ];
    pub const PUBKEY_STR: &str = "9c76823dbdb9bf048fc5c2af000e28a148ee021999fb7f21ca1f84b8fe73d7e8";
    pub static mut DEC_CTX: Option<DecryptionContext> = None;
    static DEC_CTX_INIT: std::sync::Once = std::sync::Once::new();
    pub fn init_dec_ctx() {
        unsafe {
            DEC_CTX_INIT.call_once(|| {
                DEC_CTX = Some(DecryptionContext::load_from_file(None).unwrap());
            });
        }
    }
    pub fn sha256sum(buf: &Vec<u8>) -> [u8; 32] {
        Sha256::digest(buf).into()
    }
    pub struct XorShift {
        x: u32,
        y: u32,
        z: u32,
        w: u32,
    }
    impl Default for XorShift {
        fn default() -> Self {
            Self {
                x: 123456789,
                y: 362436069,
                z: 521288629,
                w: 88675123,
            }
        }
    }
    impl XorShift {
        pub fn next(&mut self) -> u32 {
            let t = self.x ^ (self.x << 11);
            self.x = self.y; self.y = self.z; self.z = self.w;
            self.w = (self.w ^ (self.w >> 19)) ^ (t ^ (t >> 8));
            self.w
        }
    }
    #[derive(Default)]
    pub struct XorShiftRng {
        xorshift: XorShift,
    }
    impl Rng for XorShiftRng {
        fn next(&mut self) -> Scalar {
            let mut buf = [0u8; 32];
            for i in 0..32 {
                buf[i] = (self.xorshift.next() & 0xff) as u8;
            }
            buf[31] &= 0x1fu8;
            Scalar::from_bits(buf)
        }
    }
}
