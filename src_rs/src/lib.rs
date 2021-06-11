use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;

pub mod ecelgamal;
pub mod selector;

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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    pub fn sha256sum(buf: &Vec<u8>) -> [u8; 32] {
        Sha256::digest(buf).into()
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
