#[allow(unused_imports)]
use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};
use std::sync::mpsc::channel;
use rayon::prelude::*;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use crate::*;

fn format_as_hex(f: &mut std::fmt::Formatter<'_>, bytes: &[u8]) -> std::fmt::Result {
    for i in 0..bytes.len() {
        write!(f, "{:02x}", bytes[i])?;
    }
    Ok(())
}

/// Ciphertext.
#[derive(Debug)]
pub struct Cipher {
    c1: CompressedEdwardsY,
    c2: CompressedEdwardsY,
}

impl From<&[u8; CIPHER_SIZE]> for Cipher {
    fn from(buf: &[u8; CIPHER_SIZE]) -> Self {
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

impl From<&Cipher> for [u8; CIPHER_SIZE] {
    fn from(cipher: &Cipher) -> [u8; CIPHER_SIZE] {
        let mut buf = [0u8; CIPHER_SIZE];
        let (l, r) = buf.split_at_mut(POINT_SIZE);
        l.copy_from_slice(cipher.c1.as_bytes());
        r.copy_from_slice(cipher.c2.as_bytes());
        buf
    }
}

pub trait Encrypt {
    fn encrypt<R: Rng>(&self, msg: &Scalar, rng: &mut R) -> Cipher;
}

/// A private key.
#[derive(Debug, PartialEq)]
pub struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        Self {
            scalar: rng.next(),
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
    fn encrypt<R: Rng>(&self, msg: &Scalar, rng: &mut R) -> Cipher {
        let r = rng.next();
        Cipher{
            c1: ED25519_BASEPOINT_TABLE.basepoint_mul(&r).compress(),
            c2: ED25519_BASEPOINT_TABLE.basepoint_mul(&(&r * self.scalar + msg)).compress(),
        }
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.scalar.as_bytes();
        format_as_hex(f, bytes)
    }
}

/// A public key.
#[derive(Debug, PartialEq)]
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

impl TryFrom<&[u8; POINT_SIZE]> for PublicKey {
    type Error = ();
    fn try_from(buf: &[u8; POINT_SIZE]) -> Result<Self, Self::Error> {
        let point = CompressedEdwardsY::from_slice(buf).decompress();
        match point {
            Some(point) => Ok(Self { point }),
            None => Err(()),
        }
    }
}

impl Encrypt for PublicKey {
    fn encrypt<R: Rng>(&self, msg: &Scalar, rng: &mut R) -> Cipher {
        let r = rng.next();
        Cipher{
            c1: ED25519_BASEPOINT_TABLE.basepoint_mul(&r).compress(),
            c2: (&r * self.point + ED25519_BASEPOINT_TABLE.basepoint_mul(msg)).compress(),
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

#[derive(Debug, Clone)]
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
    pub fn generate_no_sort<CB>(mmax: Option<u32>, cb: Option<CB>) -> Vec<MGEntry>
        where CB: FnMut(u32) -> ()
    {
        let mmax = mmax.unwrap_or(DEFAULT_MMAX);
        let one = ED25519_BASEPOINT_POINT;
        let n_threads = num_cpus::get();
        let mut points = Vec::new();
        points.push(EIGHT_TORSION[0]);
        for i in 1..n_threads {
            points.push(points[i - 1] + one);
        }
        let tg = points[n_threads - 1] + one;
        let (tx, rx) = channel();
        for thread_id in 0..n_threads {
            let mut point = points[thread_id].clone();
            let tg = tg.clone();
            let tx = tx.clone();
            let mmax = mmax;
            std::thread::spawn(move || {
                let mut scalar = thread_id as u32;
                tx.send(MGEntry {
                    point: point.compress().to_bytes(),
                    scalar,
                }).unwrap();
                loop {
                    scalar += n_threads as u32;
                    if scalar >= mmax {
                        break;
                    }
                    point += tg;
                    tx.send(MGEntry {
                        point: point.compress().to_bytes(),
                        scalar,
                    }).unwrap();
                }
            });
        }
        let mut result = Vec::new();
        let mut pc = 0;
        if let Some(mut func) = cb {
            for entry in rx {
                result.push(entry);
                pc += 1;
                func(pc);
                if pc == mmax {
                    break;
                }
            }
        } else {
            for entry in rx {
                result.push(entry);
                pc += 1;
                if pc == mmax {
                    break;
                }
            }
        }
        result
    }
    pub fn generate_sort(mgs: &mut Vec<MGEntry>) {
        mgs.par_sort_unstable();
    }
    pub fn generate<CB>(mmax: Option<u32>, cb: Option<CB>) -> Self
        where CB: FnMut(u32) -> ()
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
    pub fn save_to_file(&self, path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::File::create(path.unwrap_or(&mg_default_path()?))?;
        let mut writer = std::io::BufWriter::new(file);
        for entry in self.mgs.iter() {
            writer.write(&entry.point)?;
            writer.write(&[
                ((entry.scalar >>  0) & 0xff) as u8,
                ((entry.scalar >>  8) & 0xff) as u8,
                ((entry.scalar >> 16) & 0xff) as u8,
                ((entry.scalar >> 24) & 0xff) as u8,
            ])?;
        }
        Ok(())
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
    use crate::tests::*;
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
        let mut rng: DefaultRng = Default::default();
        PrivateKey::new(&mut rng);
    }
    #[test]
    fn display_private_key() {
        let privkey = PrivateKey::from(PRIVKEY);
        let privkey_str = format!("{}", privkey);
        assert_eq!(privkey_str, PRIVKEY_STR);
    }
    #[test]
    fn create_public_key() {
        let pubkey = PublicKey::new(&PRIVKEY.into());
        assert_eq!(pubkey, (&PUBKEY).try_into().unwrap());
    }
    #[test]
    fn display_public_key() {
        let pubkey: PublicKey = (&PUBKEY).try_into().unwrap();
        let pubkey_str = format!("{}", pubkey);
        assert_eq!(pubkey_str, PUBKEY_STR);
    }
    #[test]
    fn encrypt_normal() {
        let pubkey: PublicKey = (&PUBKEY).try_into().unwrap();
        let mut rng = ConstRng::new(vec![Scalar::from_bits(R)]);
        let cipher = pubkey.encrypt(&MSG.into(), &mut rng);
        assert_eq!(cipher, (&CIPHER).into());
    }
    #[test]
    fn encrypt_fast() {
        let privkey = PrivateKey::from(PRIVKEY);
        let mut rng = ConstRng::new(vec![Scalar::from_bits(R)]);
        let cipher = privkey.encrypt(&MSG.into(), &mut rng);
        assert_eq!(cipher, (&CIPHER).into());
    }
    #[test]
    fn mg_generate() {
        let mut points_computed = 0;
        let dec_ctx = DecryptionContext::generate(Some(SMALL_MMAX), Some(|pc: u32| {
            points_computed += 1;
            assert_eq!(pc, points_computed);
        }));
        assert_eq!(points_computed, SMALL_MMAX);
        assert_eq!(sha256sum(&dec_ctx.into()), MG_HASH_SMALL);
    }
    #[test]
    fn mg_interpolation_search() {
        let dec_ctx = DecryptionContext::generate(Some(SMALL_MMAX), None::<fn(_)>);
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
            let decrypted = DEC_CTX.decrypt_cipher(&PRIVKEY.into(), &(&CIPHER).into());
            assert_eq!(decrypted, Ok(MSG));
        }
    }
    #[test]
    fn decrypt_fail() {
        init_dec_ctx();
        unsafe {
            let decrypted = DEC_CTX.decrypt_cipher(&PUBKEY.into(), &(&CIPHER).into());
            assert_eq!(decrypted, Err(()));
        }
    }
    #[test]
    fn random_encrypt_normal() {
        let pubkey: PublicKey = (&PUBKEY).try_into().unwrap();
        let mut rng: DefaultRng = Default::default();
        let cipher = pubkey.encrypt(&MSG.into(), &mut rng);
        init_dec_ctx();
        unsafe {
            let decrypted = DEC_CTX.decrypt_cipher(&PRIVKEY.into(), &cipher);
            assert_eq!(decrypted, Ok(MSG));
        }
    }
    #[test]
    fn random_encrypt_fast() {
        let privkey = PrivateKey::from(PRIVKEY);
        let mut rng: DefaultRng = Default::default();
        let cipher = privkey.encrypt(&MSG.into(), &mut rng);
        init_dec_ctx();
        unsafe {
            let decrypted = DEC_CTX.decrypt_cipher(&PRIVKEY.into(), &cipher);
            assert_eq!(decrypted, Ok(MSG));
        }
    }
}
