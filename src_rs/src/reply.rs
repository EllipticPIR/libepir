use rayon::prelude::*;
use crate::*;
use crate::ecelgamal::*;

fn divide_up(a: usize, b: usize) -> usize {
    (a / b) + (if a % b == 0 { 0 } else { 1 })
}

/// Returns true if `packing` is in the range [1, PACKING_MAX].
pub fn packing_is_valid(packing: u8) -> bool {
    packing >= 1 && packing <= PACKING_MAX
}

/// Computes the size of a reply. Returns 0 if `packing` is out of range.
pub fn reply_size(dimension: u8, packing: u8, elem_size: usize) -> usize {
    if !packing_is_valid(packing) {
        return 0;
    }
    let mut target_size = elem_size;
    for _ in 0..dimension {
        target_size = CIPHER_SIZE * divide_up(target_size, packing as usize);
    }
    target_size
}

/// Computes the number of randomness used by `Reply::mock()`. Returns 0 if `packing` is out of range.
pub fn reply_r_count(dimension: u8, packing: u8, elem_size: usize) -> usize {
    if !packing_is_valid(packing) {
        return 0;
    }
    let mut r_count = 0;
    let mut target_size = elem_size;
    for _ in 0..dimension {
        let tmp = divide_up(target_size, packing as usize);
        r_count += tmp;
        target_size = CIPHER_SIZE * tmp;
    }
    r_count
}

#[derive(Clone)]
pub struct Reply {
    ciphers: Vec<Cipher>,
}

impl From<&Reply> for Vec<u8> {
    fn from(reply: &Reply) -> Vec<u8> {
        let mut buf = Vec::new();
        for i in 0..reply.ciphers.len() {
            let ser: [u8; CIPHER_SIZE] = (&reply.ciphers[i]).into();
            buf.push(ser.to_vec());
        }
        buf.concat()
    }
}

impl From<&Vec<u8>> for Reply {
    fn from(buf: &Vec<u8>) -> Self {
        let mut i = 0;
        let mut ciphers = Vec::new();
        while (i + 1) * CIPHER_SIZE <= buf.len() {
            let mut cipher_arr: [u8; CIPHER_SIZE] = [0u8; CIPHER_SIZE];
            cipher_arr.copy_from_slice(&buf[i*CIPHER_SIZE..(i+1)*CIPHER_SIZE]);
            let cipher: Cipher = (&cipher_arr).into();
            ciphers.push(cipher);
            i += 1;
        }
        Reply {
            ciphers,
        }
    }
}

impl Reply {
    /// Decrypts a reply.
    /// Returns `Err(())` if the decryption fails, or if `dimension` is 0 or `packing` is out of range.
    pub fn decrypt(&self, dec_ctx: &DecryptionContext, privkey: &PrivateKey, dimension: u8, packing: u8) -> Result<Vec<u8>, ()> {
        if dimension == 0 || !packing_is_valid(packing) {
            return Err(());
        }
        let mut reply = self.clone();
        let mut ser = Vec::new();
        for dim in 0..dimension {
            let decrypteds: Vec<Result<u32, ()>> = reply.ciphers.par_iter().map(|cipher| {
                dec_ctx.decrypt(privkey, &cipher)
            }).collect();
            for i in 0..decrypteds.len() {
                let decrypted = decrypteds[i]?;
                for p in 0..packing {
                    ser.push(((decrypted >> (8 * (p as u32))) & 0xff) as u8);
                }
            }
            if dim != dimension - 1 {
                reply = (&ser).into();
                ser = Vec::new();
            }
        }
        Ok(ser)
    }
    /// Generates a sample server reply.
    /// Returns `Err(())` if `dimension` is 0 or `packing` is out of range.
    pub fn mock<E: Encrypt, R: Rng>(key: &E, dimension: u8, packing: u8, elem: &[u8], rng: &mut R) -> Result<Self, ()> {
        if dimension == 0 || !packing_is_valid(packing) {
            return Err(());
        }
        let mut ser = elem.to_vec();
        let mut ciphers = Vec::new();
        for dim in 0..dimension {
            ciphers = Vec::new();
            for i in 0..divide_up(ser.len(), packing as usize) {
                let mut msg = 0;
                let mut j = 0usize;
                while j < (packing as usize) && i * (packing as usize) + j < ser.len() {
                    msg |= (ser[i * (packing as usize) + j] as u32) << (8 * j);
                    j += 1;
                }
                let cipher = key.encrypt(&msg.into(), rng);
                ciphers.push(cipher);
            }
            if dim == dimension - 1 {
                break;
            }
            ser = (&Reply {
                ciphers: ciphers.clone(),
            }).into();
        }
        Ok(Reply {
            ciphers,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use super::*;
    use crate::tests::*;
    const DIMENSION: u8    =  3;
    const PACKING  : u8    =  3;
    const ELEM_SIZE: usize = 32;
    #[test]
    fn size() {
        let reply_size = reply_size(DIMENSION, PACKING, ELEM_SIZE);
        assert_eq!(reply_size, 320896usize);
    }
    #[test]
    fn r_count() {
        let r_count = reply_r_count(DIMENSION, PACKING, ELEM_SIZE);
        assert_eq!(r_count, 5260usize);
    }
    fn generate_elem() -> [u8; ELEM_SIZE] {
        let mut elem = [0u8; ELEM_SIZE];
        let mut xorshift: XorShift = Default::default();
        for i in 0..ELEM_SIZE {
            elem[i] = (xorshift.next() & 0xff) as u8;
        }
        elem
    }
    fn generate_reply(is_fast: bool) -> Reply {
        let elem = generate_elem();
        let mut rng: DefaultRng = Default::default();
        if is_fast {
            let privkey = PrivateKey::from(PRIVKEY);
            Reply::mock(&privkey, DIMENSION, PACKING, &elem, &mut rng).unwrap()
        } else {
            let pubkey: PublicKey = (&PUBKEY).try_into().unwrap();
            Reply::mock(&pubkey, DIMENSION, PACKING, &elem, &mut rng).unwrap()
        }
    }
    fn decrypt_success(is_fast: bool) {
        let privkey = PrivateKey::from(PRIVKEY);
        let reply = generate_reply(is_fast);
        init_dec_ctx();
        unsafe {
            let decrypted = reply.decrypt(&DEC_CTX.as_ref().unwrap(), &privkey, DIMENSION, PACKING);
            assert_eq!(decrypted.unwrap()[0..ELEM_SIZE], generate_elem());
        }
    }
    fn decrypt_fail(is_fast: bool) {
        let privkey = PrivateKey::from(PUBKEY);
        let reply = generate_reply(is_fast);
        init_dec_ctx();
        unsafe {
            let decrypted = reply.decrypt(&DEC_CTX.as_ref().unwrap(), &privkey, DIMENSION, PACKING);
            assert_eq!(decrypted, Err(()));
        }
    }
    #[test]
    fn decrypt_normal_success() {
        decrypt_success(false);
    }
    #[test]
    fn decrypt_normal_fail() {
        decrypt_fail(false);
    }
    #[test]
    fn decrypt_fast_success() {
        decrypt_success(true);
    }
    #[test]
    fn decrypt_fast_fail() {
        decrypt_fail(true);
    }
    #[test]
    fn size_reject_invalid_packing() {
        for packing in [0u8, PACKING_MAX + 1, 64, 255] {
            assert_eq!(reply_size(DIMENSION, packing, ELEM_SIZE), 0, "packing={}", packing);
            assert_eq!(reply_r_count(DIMENSION, packing, ELEM_SIZE), 0, "packing={}", packing);
        }
        assert!(reply_size(DIMENSION, PACKING_MAX, ELEM_SIZE) > 0);
        assert!(reply_r_count(DIMENSION, PACKING_MAX, ELEM_SIZE) > 0);
    }
    #[test]
    fn mock_reject_invalid_parameters() {
        let privkey = PrivateKey::from(PRIVKEY);
        let elem = generate_elem();
        let mut rng: DefaultRng = Default::default();
        for packing in [0u8, PACKING_MAX + 1, 64, 255] {
            assert!(Reply::mock(&privkey, DIMENSION, packing, &elem, &mut rng).is_err(), "packing={}", packing);
        }
        assert!(Reply::mock(&privkey, 0, PACKING, &elem, &mut rng).is_err());
    }
    #[test]
    fn decrypt_reject_invalid_parameters() {
        let privkey = PrivateKey::from(PRIVKEY);
        let reply = generate_reply(true);
        init_dec_ctx();
        unsafe {
            let dec_ctx = DEC_CTX.as_ref().unwrap();
            for packing in [0u8, PACKING_MAX + 1, 32, 64, 255] {
                assert_eq!(reply.decrypt(dec_ctx, &privkey, DIMENSION, packing), Err(()), "packing={}", packing);
            }
            assert_eq!(reply.decrypt(dec_ctx, &privkey, 0, PACKING), Err(()));
        }
    }
}
