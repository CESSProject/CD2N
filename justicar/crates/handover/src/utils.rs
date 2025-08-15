use crate::HandoverResult as Result;
use crate::SgxError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::{Key, KeyInit};
use rand::rngs::OsRng;
use ring::rand::SecureRandom;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub type EcdhSecretKey = EphemeralSecret;
pub type EcdhPublicKey = PublicKey;

pub fn gen_ecdh_key_pair() -> (EcdhSecretKey, EcdhPublicKey) {
    let ecdh_secret_key = EphemeralSecret::random_from_rng(OsRng);
    let ecdh_public_key = PublicKey::from(&ecdh_secret_key);

    return (ecdh_secret_key, ecdh_public_key);
}

pub(crate) fn generate_random_byte<const SIZE: usize>() -> [u8; SIZE] {
    let mut nonce_vec = [0u8; SIZE];
    let rand = ring::rand::SystemRandom::new();
    rand.fill(&mut nonce_vec).unwrap();
    nonce_vec
}

pub(crate) fn echd_key_agreement(
    my_ecdh_secret_key: EcdhSecretKey,
    other_ecdh_public_key: EcdhPublicKey,
) -> SharedSecret {
    my_ecdh_secret_key.diffie_hellman(&other_ecdh_public_key)
}

pub(crate) fn convert_bytes_to_ecdh_public_key(bytes: [u8; 32]) -> EcdhPublicKey {
    PublicKey::from(bytes)
}

pub(crate) fn encrypt_secret_with_shared_key(
    secret_data: &[u8],
    shared_key: &SharedSecret,
    iv: &[u8; 12],
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(shared_key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    let ciphertext = cipher
        .encrypt(nonce, secret_data)
        .map_err(|e| SgxError::CryptoError(e.to_string()))?;
    Ok(ciphertext)
}

pub(crate) fn decrypt_secret_with_shared_key(
    encrypted_data: &[u8],
    shared_key: &SharedSecret,
    iv: &[u8; 12],
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(shared_key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| SgxError::CryptoError(e.to_string()))?;
    Ok(plaintext)
}
