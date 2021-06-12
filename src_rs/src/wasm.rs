use std::convert::TryInto;
use wasm_bindgen::prelude::*;
use crate::*;
use crate::ecelgamal::*;

fn vec_to_u8_32(vec: &Vec<u8>) -> [u8; 32] {
    let mut arr = [0u8; SCALAR_SIZE];
    arr.copy_from_slice(&vec[..]);
    arr
}

fn vec_to_privkey(privkey_vec: &Vec<u8>) -> PrivateKey {
    vec_to_u8_32(privkey_vec).into()
}

fn vec_to_pubkey(pubkey_vec: &Vec<u8>) -> PublicKey {
    (&vec_to_u8_32(pubkey_vec)).try_into().unwrap()
}

#[wasm_bindgen]
pub fn create_pubkey(privkey_vec: Vec<u8>) -> Vec<u8> {
    let privkey = vec_to_privkey(&privkey_vec);
    let pubkey = PublicKey::new(&privkey);
    let pubkey_arr: [u8; POINT_SIZE] = (&pubkey).into();
    pubkey_arr.to_vec()
}

#[wasm_bindgen]
pub fn encrypt(pubkey_vec: Vec<u8>, msg: u32, r_vec: Vec<u8>) -> Vec<u8> {
    let pubkey = vec_to_pubkey(&pubkey_vec);
    let mut rng = ConstRng::new(vec![Scalar::from_bits(vec_to_u8_32(&r_vec))]);
    let cipher = pubkey.encrypt(&msg.into(), &mut rng);
    let cipher_arr: [u8; CIPHER_SIZE] = (&cipher).into();
    cipher_arr.to_vec()
}

#[wasm_bindgen]
pub fn encrypt_fast(privkey_vec: Vec<u8>, msg: u32, r_vec: Vec<u8>) -> Vec<u8> {
    let privkey = vec_to_privkey(&privkey_vec);
    let mut rng = ConstRng::new(vec![Scalar::from_bits(vec_to_u8_32(&r_vec))]);
    let cipher = privkey.encrypt(&msg.into(), &mut rng);
    let cipher_arr: [u8; CIPHER_SIZE] = (&cipher).into();
    cipher_arr.to_vec()
}
