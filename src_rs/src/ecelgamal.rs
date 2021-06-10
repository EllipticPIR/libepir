#[allow(unused_imports)]
use std::convert::{TryFrom, TryInto};
use std::io::Read;
use rayon::prelude::*;
use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

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

fn format_as_hex(f: &mut std::fmt::Formatter<'_>, bytes: &[u8]) -> std::fmt::Result {
    for i in 0..bytes.len() {
        write!(f, "{:02x}", bytes[i])?;
    }
    Ok(())
}

/// Get a random Scalar.
pub fn random_scalar() -> Scalar {
    let mut csprng = OsRng;
    Scalar::random(&mut csprng)
}

/// Ciphertext.
#[derive(Debug)]
pub struct Cipher {
    c1: CompressedEdwardsY,
    c2: CompressedEdwardsY,
}

impl From<[u8; CIPHER_SIZE]> for Cipher {
    fn from(buf: [u8; CIPHER_SIZE]) -> Self {
        Self {
            c1: CompressedEdwardsY::from_slice(&buf[0..POINT_SIZE]),
            c2: CompressedEdwardsY::from_slice(&buf[POINT_SIZE..CIPHER_SIZE]),
        }
    }
}

impl PartialEq for Cipher {
    fn eq(&self, other: &Self) -> bool {
        (self.c1 == other.c1) && (self.c2 == other.c2)
    }
}

pub trait Encrypt {
    fn encrypt(&self, msg: &Scalar, r: Option<&Scalar>) -> Cipher;
}

/// A private key.
#[derive(Debug)]
pub struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    pub fn new() -> Self {
        Self {
            scalar: random_scalar(),
        }
    }
}

impl From<[u8; SCALAR_SIZE]> for PrivateKey {
    fn from(buf: [u8; SCALAR_SIZE]) -> Self {
        Self {
            scalar: Scalar::from_bits(buf),
        }
    }
}

impl Encrypt for PrivateKey {
    fn encrypt(&self, msg: &Scalar, r: Option<&Scalar>) -> Cipher {
        let rr = match r {
            Some(r) => *r,
            None => random_scalar(),
        };
        Cipher{
            c1: ED25519_BASEPOINT_TABLE.basepoint_mul(&rr).compress(),
            c2: ED25519_BASEPOINT_TABLE.basepoint_mul(&(&rr * self.scalar + msg)).compress(),
        }
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.scalar == other.scalar
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.scalar.as_bytes();
        format_as_hex(f, bytes)
    }
}

/// A public key.
#[derive(Debug)]
pub struct PublicKey {
    point: EdwardsPoint,
}

impl PublicKey {
    pub fn new(privkey: &PrivateKey) -> Self {
        Self {
            point: ED25519_BASEPOINT_TABLE.basepoint_mul(&privkey.scalar),
        }
    }
}

impl TryFrom<[u8; POINT_SIZE]> for PublicKey {
    type Error = ();
    fn try_from(buf: [u8; POINT_SIZE]) -> Result<Self, Self::Error> {
        let point = CompressedEdwardsY::from_slice(&buf).decompress();
        match point {
            Some(point) => Ok(Self { point }),
            None => Err(()),
        }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl Encrypt for PublicKey {
    fn encrypt(&self, msg: &Scalar, r: Option<&Scalar>) -> Cipher {
        let rr = match r {
            Some(r) => *r,
            None => random_scalar(),
        };
        Cipher{
            c1: ED25519_BASEPOINT_TABLE.basepoint_mul(&rr).compress(),
            c2: (&rr * self.point + ED25519_BASEPOINT_TABLE.basepoint_mul(msg)).compress(),
        }
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let compressed = self.point.compress();
        let bytes = compressed.as_bytes();
        format_as_hex(f, bytes)
    }
}

#[derive(Clone)]
pub struct MGEntry {
    point: [u8; POINT_SIZE],
    scalar: u32,
}

fn load_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24) |
    ((bytes[1] as u32) << 16) |
    ((bytes[2] as u32) <<  8) |
    ((bytes[3] as u32) <<  0)
}

impl MGEntry {
    fn load_u32(&self) -> u32 {
        load_u32(&self.point)
    }
}

impl PartialEq for MGEntry {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl Eq for MGEntry {}

impl PartialOrd for MGEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.point.partial_cmp(&other.point)
    }
}

impl Ord for MGEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.point.cmp(&other.point)
    }
}

/// A decryption context.
#[derive(Clone)]
pub struct DecryptionContext {
    mgs: Vec<MGEntry>,
}

impl DecryptionContext {
    pub fn generate_no_sort<F>(mmax: Option<u32>, mut cb: F) -> Vec<MGEntry>
        where F: FnMut(u32)
    {
        let one = ED25519_BASEPOINT_POINT;
        let mut result = Vec::new();
        let mut point = EIGHT_TORSION[0];
        let mut points_computed = 0;
        for scalar in 0..mmax.unwrap_or(DEFAULT_MMAX) {
            result.push(MGEntry {
                point: point.compress().to_bytes(),
                scalar,
            });
            points_computed += 1;
            cb(points_computed);
            point += one;
        }
        result
    }
    pub fn generate_sort(mgs: &mut Vec<MGEntry>) {
        mgs.sort_unstable();
    }
    pub fn generate<F>(mmax: Option<u32>, cb: F) -> Self
        where F: FnMut(u32)
    {
        let mut mgs = Self::generate_no_sort(mmax, cb);
        Self::generate_sort(&mut mgs);
        Self {
            mgs,
        }
    }
    pub fn load_from_file(path: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path.unwrap_or(&mg_default_path()?))?;
        let mut reader = std::io::BufReader::new(file);
        let mut mgs = Vec::new();
        loop {
            let mut buf = [0u8; 36];
            let result = reader.read_exact(&mut buf);
            if let Err(_) = result {
                return Ok(mgs.into());
            };
            let mut point = [0; POINT_SIZE];
            point.copy_from_slice(&buf[0..32]);
            let scalar =
                ((buf[32] as u32) <<  0) |
                ((buf[33] as u32) <<  8) |
                ((buf[34] as u32) << 16) |
                ((buf[35] as u32) << 24);
            mgs.push(MGEntry {
                point,
                scalar,
            });
        }
    }
    pub fn interpolation_search(&self, mg: &[u8; 32]) -> Option<u32> {
        let mut imin = 0;
        let mut imax = self.mgs.len() - 1;
        let mut left = self.mgs[0].load_u32();
        let mut right = self.mgs[self.mgs.len() - 1].load_u32();
        let me = load_u32(mg);
        while imin <= imax {
            if left >= right {
                return None;
            }
            let imid = imin + (imax - imin) * ((me - left) as usize) / ((right - left) as usize);
            if imid < imin || imid > imax {
                return None;
            }
            if self.mgs[imid].point == *mg {
                return Some(self.mgs[imid].scalar);
            }
            if self.mgs[imid].point < *mg {
                imin = imid + 1;
                left = self.mgs[imid].load_u32();
            } else {
                imax = imid - 1;
                right = self.mgs[imid].load_u32();
            }
        }
        return None;
    }
    pub fn decrypt_to_mg(privkey: &PrivateKey, c: &Cipher) -> Result<CompressedEdwardsY, ()> {
        let c1 = match c.c1.decompress() {
            Some(c1) => c1,
            None => return Err(()),
        };
        let c2 = match c.c2.decompress() {
            Some(c2) => c2,
            None => return Err(()),
        };
        Ok((c2 - privkey.scalar * c1).compress())
    }
    pub fn decrypt_cipher(&self, privkey: &PrivateKey, c: &Cipher) -> Result<u32, ()> {
        let mg = Self::decrypt_to_mg(privkey, c)?;
        self.interpolation_search(mg.as_bytes()).ok_or(())
    }
}

impl From<DecryptionContext> for Vec<u8> {
    fn from(dec_ctx: DecryptionContext) -> Self {
        let mut vec = Vec::new();
        for mg_entry in dec_ctx.mgs.iter() {
            let mut ser = Vec::from(mg_entry.point);
            ser.push(((mg_entry.scalar >>  0) & 0xff) as u8);
            ser.push(((mg_entry.scalar >>  8) & 0xff) as u8);
            ser.push(((mg_entry.scalar >> 16) & 0xff) as u8);
            ser.push(((mg_entry.scalar >> 24) & 0xff) as u8);
            vec.push(ser);
        }
        vec.concat()
    }
}

impl From<Vec<MGEntry>> for DecryptionContext {
    fn from(mgs: Vec<MGEntry>) -> Self {
        DecryptionContext {
            mgs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    const PRIVKEY: [u8; SCALAR_SIZE] = [
        0x7e, 0xf6, 0xad, 0xd2, 0xbe, 0xd5, 0x9a, 0x79,
        0xba, 0x6e, 0xdc, 0xfb, 0xa4, 0x8f, 0xde, 0x7a,
        0x55, 0x31, 0x75, 0x4a, 0xf5, 0x93, 0x76, 0x34,
        0x6c, 0x8b, 0x52, 0x84, 0xee, 0xf2, 0x52, 0x07,
    ];
    const PUBKEY: [u8; POINT_SIZE] = [
        0x9c, 0x76, 0x82, 0x3d, 0xbd, 0xb9, 0xbf, 0x04,
        0x8f, 0xc5, 0xc2, 0xaf, 0x00, 0x0e, 0x28, 0xa1,
        0x48, 0xee, 0x02, 0x19, 0x99, 0xfb, 0x7f, 0x21,
        0xca, 0x1f, 0x84, 0xb8, 0xfe, 0x73, 0xd7, 0xe8,
    ];
    const MSG: u32 = (0x12345678 & (DEFAULT_MMAX - 1)) as u32;
    const R: [u8; SCALAR_SIZE] = [
        0x42, 0xff, 0x2d, 0x98, 0x4a, 0xe5, 0xa2, 0x8f,
        0x7d, 0x02, 0x69, 0x87, 0xc7, 0x10, 0x9a, 0x7b,
        0x3a, 0x1d, 0x36, 0x58, 0x82, 0x5a, 0x09, 0x17,
        0xe1, 0x69, 0x3e, 0x83, 0xa5, 0x71, 0x5d, 0x09,
    ];
    const CIPHER: [u8; CIPHER_SIZE] = [
        0x11, 0xa9, 0x4e, 0xb7, 0x18, 0x53, 0x7e, 0x94,
        0x7d, 0x0f, 0xf3, 0x0c, 0xdd, 0xae, 0x16, 0xae,
        0xab, 0x42, 0x9e, 0xac, 0x09, 0x2b, 0x22, 0x00,
        0x06, 0xb1, 0x9c, 0xcc, 0xb5, 0x26, 0xb4, 0x30,
        0xeb, 0x76, 0x83, 0xc0, 0xdf, 0x90, 0x3a, 0x88,
        0xf6, 0xf1, 0x09, 0x52, 0xbc, 0xa4, 0xd6, 0x45,
        0x28, 0x4f, 0xf7, 0xed, 0x95, 0xc6, 0xa4, 0xe9,
        0x67, 0xf5, 0xe7, 0xae, 0x22, 0xc9, 0x33, 0xcb,
    ];
    const SMALL_MMAX_MOD: u8 = 16;
    const SMALL_MMAX: u32 = 1 << SMALL_MMAX_MOD;
    const MG_HASH_SMALL: [u8; 32] = [
        0x8c, 0x55, 0x49, 0x7e, 0x28, 0xd5, 0xea, 0x75,
        0x15, 0xdd, 0x32, 0xb3, 0x98, 0x34, 0x0b, 0xfa,
        0xf8, 0x89, 0x40, 0x35, 0xe0, 0x30, 0xd2, 0x13,
        0x50, 0x80, 0x84, 0x31, 0xb8, 0x00, 0x8a, 0xf2
    ];
    #[test]
    fn create_private_key() {
        PrivateKey::new();
    }
    #[test]
    fn create_public_key() {
        let pubkey = PublicKey::new(&PRIVKEY.into());
        assert_eq!(pubkey, PUBKEY.try_into().unwrap());
    }
    #[test]
    fn encrypt_normal() {
        let pubkey = PublicKey::new(&PRIVKEY.into());
        let cipher = pubkey.encrypt(&MSG.into(), Some(&Scalar::from_bits(R)));
        assert_eq!(cipher, CIPHER.into());
    }
    #[test]
    fn encrypt_fast() {
        let privkey = PrivateKey::from(PRIVKEY);
        let cipher = privkey.encrypt(&MSG.into(), Some(&Scalar::from_bits(R)));
        assert_eq!(cipher, CIPHER.into());
    }
    fn sha256sum(buf: &Vec<u8>) -> [u8; 32] {
        Sha256::digest(buf).into()
    }
    #[test]
    fn mg_generate() {
        let mut points_computed = 0;
        let dec_ctx = DecryptionContext::generate(Some(SMALL_MMAX), |points_computed_test| {
            points_computed += 1;
            assert_eq!(points_computed_test, points_computed);
        });
        assert_eq!(sha256sum(&dec_ctx.into()), MG_HASH_SMALL);
    }
    #[test]
    fn mg_interpolation_search() {
        let dec_ctx = DecryptionContext::generate(Some(SMALL_MMAX), |_| {});
        for i in 0..SMALL_MMAX {
            let scalar = dec_ctx.interpolation_search(&dec_ctx.mgs[i as usize].point);
            assert_eq!(scalar, Some(dec_ctx.mgs[i as usize].scalar));
        }
    }
    #[test]
    fn mg_default_path() {
        assert_eq!(super::mg_default_path().unwrap(), std::env::var("HOME").unwrap() + "/.EllipticPIR/mG.bin");
    }
    static mut DEC_CTX: DecryptionContext = DecryptionContext { mgs: Vec::new(), };
    static DEC_CTX_INIT: std::sync::Once = std::sync::Once::new();
    fn init_dec_ctx() {
        unsafe {
            DEC_CTX_INIT.call_once(|| {
                DEC_CTX = DecryptionContext::load_from_file(None).unwrap();
            });
        }
    }
    #[test]
    fn decrypt_success() {
        init_dec_ctx();
        unsafe {
            let decrypted = DEC_CTX.decrypt_cipher(&PRIVKEY.into(), &CIPHER.into());
            assert_eq!(decrypted, Ok(MSG));
        }
    }
    #[test]
    fn decrypt_fail() {
        init_dec_ctx();
        unsafe {
            let decrypted = DEC_CTX.decrypt_cipher(&PUBKEY.into(), &CIPHER.into());
            assert_eq!(decrypted, Err(()));
        }
    }
    #[test]
    fn random_encrypt_normal() {
        let pubkey = PublicKey::new(&PRIVKEY.into());
        let cipher = pubkey.encrypt(&MSG.into(), None);
        init_dec_ctx();
        unsafe {
            let decrypted = DEC_CTX.decrypt_cipher(&PRIVKEY.into(), &cipher);
            assert_eq!(decrypted, Ok(MSG));
        }
    }
    #[test]
    fn random_encrypt_fast() {
        let privkey = PrivateKey::from(PRIVKEY);
        let cipher = privkey.encrypt(&MSG.into(), None);
        init_dec_ctx();
        unsafe {
            let decrypted = DEC_CTX.decrypt_cipher(&PRIVKEY.into(), &cipher);
            assert_eq!(decrypted, Ok(MSG));
        }
    }
}
