package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mholt/archiver"
	"github.com/vedhavyas/go-subkey/sr25519"
	"github.com/vedhavyas/go-subkey/v2"

	ecies "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

const (
	ARCHIVER_FORMAT_ZIP   = "zip"
	ARCHIVER_FORMAT_TAR   = "tar"
	ARCHIVER_FORMAT_TARGZ = "tar.gz"

	UNNAMED_FILENAME = "Unnamed"
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

	pri, err := sr25519.Scheme{}.FromPhrase(mnemonic, "")
	if err != nil {
		return nil, errors.New("invalid mnemonic")
	}
	return pri.Sign([]byte(msg))
}

func VerifySR25519WithPublickey(msg, sign, pubkey []byte) (bool, error) {
	public, err := sr25519.Scheme{}.FromPublicKey(pubkey)
	if err != nil {
		return false, err
	}
	ok := public.Verify(msg, sign)
	return ok, err
}

type Archiver interface {
	Archive(files []string, dest string) error
	Unarchive(src, dest string) error
	Extract(src string, target string, dest string) error
	Close() error
}

func NewArchiver(archiveFormat string) (Archiver, error) {
	var ar Archiver
	switch archiveFormat {
	case ARCHIVER_FORMAT_ZIP:
		ar = archiver.NewZip()
	case ARCHIVER_FORMAT_TAR:
		ar = archiver.NewTar()

	case ARCHIVER_FORMAT_TARGZ:
		ar = archiver.NewTarGz()
	default:
		err := errors.New("unsupported archive format")
		return nil, errors.Wrap(err, "compress data error")
	}
	return ar, nil
}

func CalcSha256Hash(datas ...[]byte) []byte {
	hash := sha256.New()
	for _, data := range datas {
		hash.Write(data)
	}
	return hash.Sum(nil)
}

func CalcSHA256(data []byte) (string, error) {
	if len(data) <= 0 {
		return "", errors.New("data is nil")
	}
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func GetRandomBytes() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func FillRandData(data []byte) error {
	var (
		buf []byte
		err error
	)
	for i := 0; i < len(data); i++ {
		idx := i % 32
		if idx == 0 {
			buf, err = GetRandomBytes()
			if err != nil {
				return err
			}
		}
		data[i] = buf[idx]
	}
	return nil
}

func FillZeroData(data []byte) error {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
	return nil
}

func VerifySecp256k1Sign(pubkey, data, sign []byte) bool {

	hash := crypto.Keccak256Hash(data)
	return crypto.VerifySignature(
		pubkey,
		hash.Bytes(), sign[:len(sign)-1],
	)
}

func SignWithSecp256k1PrivateKey(sk *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := crypto.Keccak256Hash(data)
	sign, err := crypto.Sign(hash.Bytes(), sk)
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func GetAESKeyEncryptedWithECDH(sk *ecies.PrivateKey, pubkey []byte) ([]byte, []byte, error) {
	var err error

	pk, err := ecies.NewPublicKeyFromBytes(pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}
	ecdhKey, err := sk.ECDH(pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}
	hashKey := sha256.Sum256(ecdhKey)
	return hashKey[:], sk.PublicKey.Bytes(true), nil
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

func Remove0x(hex string) string {
	if strings.HasPrefix(strings.ToLower(hex), "0x") {
		return hex[2:]
	}
	return hex
}

func CopyFile(src, dist string) error {
	dfile, err := os.Create(dist)
	if err != nil {
		return err
	}
	defer dfile.Close()
	sfile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sfile.Close()
	_, err = io.Copy(dfile, sfile)
	return err
}

func GetDataHash(data ...any) []byte {
	h := sha256.New()
	h.Write(fmt.Append([]byte{}, data...))
	return h.Sum(nil)
}
