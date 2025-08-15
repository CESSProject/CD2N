use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::{Key, KeyInit};
use alloy::signers::local::{coins_bip39::English, MnemonicBuilder};
use anyhow::{anyhow, Context, Result};
use bip39::{Language, Mnemonic};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub private_key: [u8; 32],
    pub public_key: Vec<u8>,
    pub mnemonic: String,
    pub eth_public_address: String,
}

pub fn generate_new_wallet() -> Result<Wallet> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12).unwrap();

    let mnemonic_phrase = mnemonic.to_string();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase(mnemonic_phrase.clone())
        .index(0)?
        .password("")
        .build()?;

    let private_key: [u8; 32] = wallet.to_bytes().0;

    let secp = Secp256k1::new();
    let public_key = SecretKey::from_slice(&private_key)
        .context("Invalid secret key size")?
        .public_key(&secp);

    Ok(Wallet {
        private_key: private_key,
        public_key: public_key.serialize().to_vec(),
        mnemonic: mnemonic_phrase,
        eth_public_address: wallet.address().to_string(),
    })
}

pub fn restore_public_key_from_golang_signature(
    signature: [u8; 65],
    message: &[u8],
) -> Result<[u8; 33]> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let msg: [u8; 32] = hasher.finalize().into();
    let msg = secp256k1::Message::from_digest(msg);

    let id = secp256k1::ecdsa::RecoveryId::try_from(i32::from(signature[signature.len() - 1]))?;
    let sig = secp256k1::ecdsa::RecoverableSignature::from_compact(&signature[..64], id)?;

    let secp = Secp256k1::new();
    let pbk = secp
        .recover_ecdsa(&msg, &sig)
        .context("Failed to recover public key from signature")?;

    Ok(pbk.serialize())
}

pub fn convert_public_key_to_eth_address(public_key: [u8; 33]) -> Result<String> {
    if public_key.len() != 33 {
        return Err(anyhow!("Invalid public key length"));
    }

    let pubkey = PublicKey::from_slice(&public_key).context("Invalid public key")?;

    let pubkey_uncompressed = pubkey.serialize_uncompressed().to_vec();

    let mut keccak = Keccak::v256();
    keccak.update(&pubkey_uncompressed[1..]);

    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let eth_address_byte = hash[12..].to_vec();

    Ok(hex::encode_upper(eth_address_byte))
}

impl Wallet {
    pub fn ecdh_agreement(&self, other_public_key: [u8; 33]) -> Result<[u8; 32]> {
        let secret_data = secp256k1::ecdh::SharedSecret::new(
            &PublicKey::from_slice(&other_public_key).context("Invalid other's public key")?,
            &SecretKey::from_slice(&self.private_key).context("Invalid my secret key")?,
        );
        Ok(secret_data.secret_bytes())
    }

    pub fn decrypt_data_with_shared_secret_and_nonce(
        &self,
        encrypted_data: &[u8],
        secret_data: [u8; 32],
        iv: &[u8; 12],
    ) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&secret_data);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(iv);
        let plaintext = cipher.decrypt(nonce, encrypted_data).map_err(|e| {
            anyhow!(
                "Failed to decrypt data from provider because: {:?}",
                e.to_string()
            )
        })?;
        Ok(plaintext)
    }

    pub fn _encrypt_data_with_shared_secret_and_nonce(
        &self,
        raw_data: &[u8],
        secret_data: [u8; 32],
        iv: &[u8; 12],
    ) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&secret_data);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(iv);

        let ciphertext = cipher.encrypt(nonce, raw_data).map_err(|e| {
            anyhow!(
                "Failed to encrypt data with shared secret because: {:?}",
                e.to_string()
            )
        })?;
        Ok(ciphertext)
    }

    pub fn _sign_data_with_wallet(&self, data: &[u8]) -> Result<[u8; 64]> {
        let sk = &SecretKey::from_slice(&self.private_key).context("Invalid my secret key")?;
        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash: [u8; 32] = hasher.finalize().into();
        let msg = secp256k1::Message::from_digest(data_hash);

        let sign = secp.sign_ecdsa(&msg, sk);

        Ok(sign.serialize_compact())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_new_wallet() -> Result<()> {
        let rand_wallet = generate_new_wallet()?;

        println!("Private Key: {:#?}", hex::encode(rand_wallet.private_key));
        println!("Public Key: {:#?}", hex::encode(rand_wallet.public_key));
        println!("Mnemonic: {:?}", rand_wallet.mnemonic);
        println!("Eth Public Address: {}", rand_wallet.eth_public_address);
        Ok(())
    }

    #[test]
    fn test_restore_public_key_from_golang_signature() -> Result<()> {
        let golang_signature_hex = "51097d349542498fd40b9ceebbe8c7c43ab921ec5b4bb4e47e7146886d2490f50f31573722939a1181d7c380cd359e2868e1790a01c410f05d063a354c6913c700";
        let golang_msg = "hello world!! test aaa bbb ccc";

        let golang_signature = hex::decode(golang_signature_hex)?;

        let pbk = restore_public_key_from_golang_signature(
            golang_signature.try_into().unwrap(),
            golang_msg.as_bytes(),
        )?;
        assert_eq!(
            pbk,
            [
                2, 85, 40, 211, 205, 90, 40, 96, 88, 74, 160, 78, 7, 173, 118, 197, 91, 198, 223,
                13, 101, 113, 112, 24, 233, 167, 66, 35, 134, 56, 176, 59, 50
            ]
        );
        Ok(())
    }

    #[test]
    fn test_convert_public_key_to_eth_address() -> Result<()> {
        let eth_address = "8aDc35e1a9a5A6217a63998821D3c413b2d4719B"
            .to_string()
            .to_uppercase();
        let eth_pbk = [
            2_u8, 85, 40, 211, 205, 90, 40, 96, 88, 74, 160, 78, 7, 173, 118, 197, 91, 198, 223,
            13, 101, 113, 112, 24, 233, 167, 66, 35, 134, 56, 176, 59, 50,
        ];

        assert_eq!(convert_public_key_to_eth_address(eth_pbk)?, eth_address);

        Ok(())
    }

    #[test]
    fn test_ecdh_agreement() -> Result<()> {
        let wallet_a = generate_new_wallet()?;
        let wallet_b = generate_new_wallet()?;
        let secret = wallet_a.ecdh_agreement(wallet_b.public_key.clone().try_into().unwrap())?;

        println!(
            "walletA private key: {:#?}",
            hex::encode(wallet_a.private_key)
        );
        println!(
            "walletA public key: {:#?}",
            hex::encode(wallet_a.public_key)
        );
        println!(
            "walletB private key: {:#?}",
            hex::encode(wallet_b.private_key)
        );
        println!(
            "walletB public key: {:#?}",
            hex::encode(wallet_b.public_key)
        );

        println!("Secret: {:#?}", hex::encode(secret));

        Ok(())
    }

    #[test]
    fn test_encrpyt_decrypt_data_with_shared_secret_and_nonce() -> Result<()> {
        let wallet_a = generate_new_wallet()?;
        let wallet_b = generate_new_wallet()?;
        let secret = wallet_a.ecdh_agreement(wallet_b.public_key.clone().try_into().unwrap())?;

        println!(
            "walletA private key: {:#?}",
            hex::encode(wallet_a.clone().private_key)
        );
        println!(
            "walletA public key: {:#?}",
            hex::encode(wallet_a.clone().public_key)
        );
        println!(
            "walletB private key: {:#?}",
            hex::encode(wallet_b.clone().private_key)
        );
        println!(
            "walletB public key: {:#?}",
            hex::encode(wallet_b.clone().public_key)
        );

        println!("Secret: {:#?}", hex::encode(secret.clone()));

        let raw_data = b"hello cd2n";
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let encrypted_data =
            wallet_a._encrypt_data_with_shared_secret_and_nonce(raw_data, secret.clone(), &iv)?;

        println!(
            "walletA encrpyted data result: {:?}",
            hex::encode(encrypted_data.clone())
        );

        let decrypted_raw_data =
            wallet_b.decrypt_data_with_shared_secret_and_nonce(&encrypted_data, secret, &iv)?;
        println!(
            "walletB decrypted data result: {:?}",
            String::from_utf8(decrypted_raw_data.clone())?
        );

        Ok(())
    }
}
