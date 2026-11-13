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

// JS numbers are taken as u32 and validated before narrowing to u8,
// so that e.g. 256 is rejected instead of silently becoming 0.
fn check_dimension(dimension: u32) -> Result<u8, JsError> {
    if dimension < 1 || dimension > u8::MAX as u32 {
        return Err(JsError::new("The parameter 'dimension' is out of range."));
    }
    Ok(dimension as u8)
}

fn check_packing(packing: u32) -> Result<u8, JsError> {
    if packing < 1 || packing > PACKING_MAX as u32 {
        return Err(JsError::new("The parameter 'packing' is out of range."));
    }
    Ok(packing as u8)
}

#[wasm_bindgen]
pub fn reply_size(dimension: u32, packing: u32, elem_size: usize) -> Result<usize, JsError> {
    Ok(crate::reply::reply_size(check_dimension(dimension)?, check_packing(packing)?, elem_size))
}

#[wasm_bindgen]
pub fn reply_r_count(dimension: u32, packing: u32, elem_size: usize) -> Result<usize, JsError> {
    Ok(crate::reply::reply_r_count(check_dimension(dimension)?, check_packing(packing)?, elem_size))
}

#[wasm_bindgen]
pub fn reply_mock(pubkey_vec: Vec<u8>, dimension: u32, packing: u32, elem: Vec<u8>, r_vec: Vec<u8>) -> Result<Vec<u8>, JsError> {
    let dimension = check_dimension(dimension)?;
    let packing = check_packing(packing)?;
    let pubkey = vec_to_pubkey(&pubkey_vec);
    // Reply::mock() takes one scalar per ciphertext; a short r_vec would make ConstRng panic.
    let r_count = crate::reply::reply_r_count(dimension, packing, elem.len());
    if r_vec.len() < r_count * SCALAR_SIZE {
        return Err(JsError::new(&format!(
            "The parameter 'r' is too short: {} bytes given, {} bytes ({} scalars) required.",
            r_vec.len(), r_count * SCALAR_SIZE, r_count)));
    }
    let mut r = Vec::new();
    for i in 0..r_vec.len()/SCALAR_SIZE {
        r.push(Scalar::from_bits(vec_to_u8_32(&r_vec[i*SCALAR_SIZE..(i+1)*SCALAR_SIZE].to_vec())));
    }
    let mut rng = ConstRng::new(r);
    let reply = Reply::mock(&pubkey, dimension, packing, &elem, &mut rng)
        .map_err(|_| JsError::new("Failed to generate a mock reply."))?;
    Ok((&reply).into())
}
