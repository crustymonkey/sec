#[cfg(test)]
extern crate base64;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use md5;
use rand_core::{OsRng, RngCore};

const IV_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub fn gen_iv() -> Vec<u8> {
    let mut ret = vec![0; IV_LEN];
    OsRng.fill_bytes(&mut ret);

    return ret;
}

pub fn hash_key(key: &[u8]) -> Vec<u8> {
    let digest = md5::compute(key);

    return format!("{:x}", digest).as_bytes().to_vec();
}

fn validate_len(name: &str, item: &[u8], valid_len: usize) -> Result<()> {
    if item.len() != valid_len {
        return Err(anyhow!("Invalid len for {}: {}", name, item.len()));
    }

    return Ok(());
}

pub fn encrypt(text: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key = hash_key(key);
    validate_len("iv", iv, IV_LEN)?;

    let keyl = Key::from_slice(&key);
    let ivl = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(keyl);
    let ret = match cipher.encrypt(&ivl, text.as_ref()) {
        Ok(val) => val,
        Err(e) => {
            return Err(anyhow!("Failed to decrypt: {}", e));
        }
    };
    return Ok(ret);
}

pub fn decrypt(enc: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key = hash_key(key);
    validate_len("iv", iv, IV_LEN)?;

    let keyl = Key::from_slice(&key);
    let ivl = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(keyl);
    let ret = match cipher.decrypt(&ivl, enc.as_ref()) {
        Ok(val) => val,
        Err(e) => {
            return Err(anyhow!("Failed to decrypt: {}", e));
        }
    };
    return Ok(ret);
}

/// Return a Vec<u8> with the iv prepended
pub fn encrypt_w_iv(text: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let ciphertext = encrypt(text, key, iv)?;
    let mut ret = vec![];

    ret.extend(iv);
    ret.extend(ciphertext);

    return Ok(ret);
}
/// Return a Vec<u8> with the iv prepended
pub fn decrypt_w_iv(enc: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let iv = &enc[..IV_LEN];
    let cipher_bytes = &enc[IV_LEN..];
    let ret = decrypt(&cipher_bytes, key, iv)?;

    return Ok(ret);
}

#[test]
fn test_hash_key() {
    let key = b"test";
    let padded = hash_key(key);
    assert_eq!(padded.len(), KEY_LEN);

    assert_eq!(padded, b"098f6bcd4621d373cade4e832627b4f6".to_vec());
}

#[test]
fn test_gen_iv() {
    let iv = gen_iv();

    assert_eq!(iv.len(), IV_LEN);
}

#[test]
fn test_validate_len() {
    let item = b"test";
    assert!(validate_len("", item, 4).is_ok());
    assert!(validate_len("", item, 5).is_err());
}

#[test]
fn test_encrypt_decrypt() {
    use base64::encode;
    let iv = b"0123456789ab";
    let key = b"password";
    let to_enc = b"this is a test";

    let encrypted = encrypt(to_enc, key, iv).unwrap();

    assert_eq!(
        encode(&encrypted),
        "FWhZFBluJH7/W30MGZGi7MJY45BaUypT7ahiR5Dv"
    );

    let decrypted = decrypt(&encrypted, key, iv).unwrap();

    assert_eq!(decrypted, to_enc.to_vec());
}

#[test]
fn test_enc_dec_w_iv() {
    use base64::encode;
    let iv = b"0123456789ab";
    let key = b"password";
    let to_enc = b"this is a test";

    let res = encrypt_w_iv(to_enc, key, iv).unwrap();

    assert_eq!(
        encode(&res),
        "MDEyMzQ1Njc4OWFiFWhZFBluJH7/W30MGZGi7MJY45BaUypT7ahiR5Dv"
    );

    let plain = decrypt_w_iv(&res, key).unwrap();

    assert_eq!(plain, to_enc.to_vec());
}
