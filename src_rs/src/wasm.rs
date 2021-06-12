use std::convert::TryInto;
use wasm_bindgen::prelude::*;
use crate::*;
use crate::ecelgamal::*;
use crate::selector::*;
use crate::reply::*;

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

#[wasm_bindgen]
pub fn ciphers_count(index_counts: Vec<u32>) -> u32 {
    let ic = IndexCount::new(&index_counts);
    ic.ciphers()
}

#[wasm_bindgen]
pub fn elements_count(index_counts: Vec<u32>) -> u32 {
    let ic = IndexCount::new(&index_counts);
    ic.elements()
}

#[wasm_bindgen]
pub fn reply_size(dimension: u8, packing: u8, elem_size: usize) -> usize {
    crate::reply::reply_size(dimension, packing, elem_size)
}

#[wasm_bindgen]
pub fn reply_r_count(dimension: u8, packing: u8, elem_size: usize) -> usize {
    crate::reply::reply_r_count(dimension, packing, elem_size)
}

#[wasm_bindgen]
pub fn reply_mock(pubkey_vec: Vec<u8>, dimension: u8, packing: u8, elem: Vec<u8>, r_vec: Vec<u8>) -> Vec<u8> {
    let pubkey = vec_to_pubkey(&pubkey_vec);
    let mut r = Vec::new();
    for i in 0..r_vec.len()/SCALAR_SIZE {
        r.push(Scalar::from_bits(vec_to_u8_32(&r_vec[i*SCALAR_SIZE..(i+1)*SCALAR_SIZE].to_vec())));
    }
    let mut rng = ConstRng::new(r);
    let reply = Reply::mock(&pubkey, dimension, packing, &elem, &mut rng);
    (&reply).into()
}
