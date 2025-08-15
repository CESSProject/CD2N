package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/cosmos/go-bip39"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/vedhavyas/go-subkey/sr25519"
	"github.com/vedhavyas/go-subkey/v2"
	"golang.org/x/exp/rand"
)

const (
	MAINNET_FORMAT = 11331
	TESTNET_FORMAT = 11330
)

func ParsingPublickey(address string) ([]byte, error) {
	_, pubkey, err := subkey.SS58Decode(address)
	return pubkey, errors.Wrap(err, "parse publick key error")
}

func EncodePubkey(pubkey []byte, format uint16) string {
	return subkey.SS58Encode(pubkey, format)
}

func SignedSR25519WithMnemonic(mnemonic string, msg string) ([]byte, error) {
	if len(msg) <= 0 {
		return nil, errors.New("SignedSR25519WithMnemonic: empty msg")
	}
	pri, err := sr25519.Scheme{}.FromPhrase(mnemonic, "")
	if err != nil {
		return nil, errors.New("SignedSR25519WithMnemonic: invalid mnemonic")
	}
	return pri.Sign([]byte(msg))
}

func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

// VerifySR25519WithPublickey verify sr25519 signature with account public key
//   - msg: message
//   - sign: sr25519 signature
//   - account: polkadot account
//
// Return:
//   - bool: verification result
//   - error: error message
func VerifySR25519WithPublickey(msg string, sign []byte, account string) (bool, error) {
	if len(sign) <= 0 {
		return false, errors.New("VerifySR25519WithPublickey: empty sign")
	}
	pk, err := ParsingPublickey(account)
	if err != nil {
		return false, errors.New("VerifySR25519WithPublickey: invalid account")
	}
	public, err := sr25519.Scheme{}.FromPublicKey(pk)
	if err != nil {
		return false, err
	}
	ok := public.Verify([]byte(msg), sign)
	return ok, err
}

func GetRandomcode(length uint8) string {
	byteSlice := make([]byte, length)
	rand.Read(byteSlice)
	return base64.URLEncoding.EncodeToString(byteSlice)
}

func Keccak256HashWithContractPrefix(hash common.Hash) common.Hash {
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	return crypto.Keccak256Hash(
		prefix,
		hash.Bytes(),
	)
}

func SignWithSecp256k1PrivateKey(sk *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := crypto.Keccak256Hash(data)
	sign, err := crypto.Sign(hash.Bytes(), sk)
	if err != nil {
		return nil, err
	}
	// if len(sign) != 65 {
	// 	return nil, errors.New("invalid signature length")
	// }
	// sign[64] += 27
	return sign, nil
}

func SignWithContractPrefix(sk string, data []byte) ([]byte, error) {
	privateKey, err := crypto.HexToECDSA(sk)
	if err != nil {
		return nil, err
	}
	hash := Keccak256HashWithContractPrefix(
		crypto.Keccak256Hash(data),
	)
	sign, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	if len(sign) != 65 {
		return nil, errors.New("invalid signature length")
	}
	sign[64] += 27
	return sign, nil
}

func AesEncrypt(data, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
}

func AesDecrypt(data, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func EncryptFile(fpath string, key, nonce []byte) (string, error) {
	var (
		newPath string
		err     error
	)
	f, err := os.Open(fpath)
	if err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}

	newPath = filepath.Join(filepath.Dir(fpath), hex.EncodeToString([]byte(fpath)))
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}
	data, err = AesEncrypt(data, key, nonce)
	if err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}
	f, err = os.Create(newPath)
	if err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return newPath, errors.Wrap(err, "encrypt file with aes error")
	}
	return newPath, nil
}

func MakeDir(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}
