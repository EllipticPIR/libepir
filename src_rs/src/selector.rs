use rayon::prelude::*;
use crate::*;
use crate::ecelgamal::*;

pub struct IndexCount {
    indexes: Vec<u32>,
}

impl IndexCount {
    pub fn new(indexes: &[u32]) -> Self {
        Self {
            indexes: indexes.to_vec(),
        }
    }
    pub fn ciphers(&self) -> u32 {
        let mut ciphers = 0;
        for i in self.indexes.iter() {
            ciphers += i;
        }
        ciphers
    }
    pub fn elements(&self) -> u32 {
        let mut elements = 1;
        for i in self.indexes.iter() {
            elements *= i;
        }
        elements
    }
}

pub struct Choice {
    choices: Vec<Vec<bool>>,
}

impl Choice {
    pub fn create(ic: &IndexCount, idx: u32) -> Self {
        let mut idx = idx;
        let mut prod = ic.elements();
        let mut choices = Vec::with_capacity(ic.indexes.len());
        for dim in 0..ic.indexes.len() {
            choices.push(Vec::with_capacity(ic.indexes[dim] as usize));
            let cols = ic.indexes[dim];
            prod /= cols;
            let rows = idx / prod;
            idx -= rows * prod;
            for r in 0..ic.indexes[dim] {
                choices[dim].push(r == rows);
            }
        }
        Self {
            choices,
        }
    }
}

pub struct Selector {
    ciphers: Vec<Vec<Cipher>>,
}

impl Selector {
    pub fn create<E, R>(key: &E, ic: &IndexCount, idx: u32, rng: &mut R) -> Self
        where E: Encrypt + Sync, R: Rng + Sync + Send
    {
        let choice = Choice::create(ic, idx);
        let mut entries = Vec::new();
        for dim in 0..ic.indexes.len() {
            entries.push(Vec::new());
            for i in 0..ic.indexes[dim] {
                entries[dim].push((choice.choices[dim][i as usize], rng.next()));
            }
        }
        let ciphers = entries.par_iter().map(|entries| {
            entries.par_iter().map(|entry| {
                let choice = entry.0;
                let scalar = entry.1;
                let mut rng = ConstRng::new(vec![scalar]);
                let msg = if choice { 1u8 } else { 0u8 };
                key.encrypt(&msg.into(), &mut rng)
            }).collect()
        }).collect();
        Self {
            ciphers,
        }
    }
}

impl From<Selector> for Vec<u8> {
    fn from(selector: Selector) -> Vec<u8> {
        let mut buf = Vec::new();
        for dim in 0..selector.ciphers.len() {
            for row in 0..selector.ciphers[dim].len() {
                let slice: [u8; CIPHER_SIZE] = (&selector.ciphers[dim][row]).into();
                buf.push(slice.to_vec());
            }
        }
        buf.concat()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use super::*;
    use crate::tests::*;
    pub const INDEX_COUNT: [u32; 3] = [1000, 1000, 1000];
    pub const CIPHERS_COUNT: u32 = 3000;
    pub const ELEMENTS_COUNT: u32 = 1_000_000_000;
    pub const IDX: u32 = 12345678;
    pub const ROWS: [u32; 3] = [IDX / 1_000_000, (IDX % 1_000_000) / 1_000, IDX % 1_000];
    pub const SELECTOR_HASH: [u8; 32] = [
        0xda, 0x20, 0x9d, 0x4f, 0x85, 0xad, 0x0d, 0xb2,
        0x68, 0x45, 0x6f, 0x0d, 0x4e, 0x9e, 0x90, 0x7f,
        0x8f, 0x87, 0x31, 0xa6, 0x69, 0x5d, 0xa5, 0x5f,
        0x1f, 0x3d, 0x19, 0x2f, 0x59, 0xac, 0xe9, 0x0c
    ];
    #[test]
    fn ciphers() {
        let ic = IndexCount::new(&INDEX_COUNT);
        assert_eq!(ic.ciphers(), CIPHERS_COUNT);
    }
    #[test]
    fn elements() {
        let ic = IndexCount::new(&INDEX_COUNT);
        assert_eq!(ic.elements(), ELEMENTS_COUNT);
    }
    #[test]
    fn choice() {
        let ic = IndexCount::new(&INDEX_COUNT);
        let choice = Choice::create(&ic, IDX);
        for dim in 0..INDEX_COUNT.len() {
            for r in 0..INDEX_COUNT[dim] {
                assert_eq!(choice.choices[dim as usize][r as usize], r == ROWS[dim]);
            }
        }
    }
    #[test]
    fn normal() {
        let pubkey: PublicKey = (&PUBKEY).try_into().unwrap();
        let ic = IndexCount::new(&INDEX_COUNT);
        let mut rng: XorShiftRng = Default::default();
        let selector = Selector::create(&pubkey, &ic, IDX, &mut rng);
        assert_eq!(sha256sum(&selector.into()), SELECTOR_HASH);
    }
    #[test]
    fn fast() {
        let privkey = PrivateKey::from(PRIVKEY);
        let ic = IndexCount::new(&INDEX_COUNT);
        let mut rng: XorShiftRng = Default::default();
        let selector = Selector::create(&privkey, &ic, IDX, &mut rng);
        assert_eq!(sha256sum(&selector.into()), SELECTOR_HASH);
    }
}
