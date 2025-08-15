package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CESSProject/cess-crypto/gosdk"
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/go-redis/redis/v8"
	"github.com/gtank/ristretto255"
	"github.com/pkg/errors"
)

const (
	IV_BYTE_LEN  = 12
	TAG_BYTE_LEN = 16

	PLAINTEXT_BLOCK_SIZE = 30<<20 - 16 // 32MiB -16B,ciphertext block size: 32MiB
)

type CryptoModule struct {
	capsules *redis.Client
	sk       *schnorrkel.SecretKey
	pubkey   *schnorrkel.PublicKey
}

type CapsuleItem struct {
	Capsule gosdk.Capsule
	Date    time.Time
}

func NewCryptoModule(capsules *redis.Client) (*CryptoModule, error) {
	sk, pk, err := schnorrkel.GenerateKeypair()
	if err != nil {
		return nil, errors.Wrap(err, "new crypto module error")
	}
	return &CryptoModule{
		capsules: capsules,
		sk:       sk,
		pubkey:   pk,
	}, nil
}

func (cm *CryptoModule) GetCapsule(did string) ([]byte, [32]byte, error) {
	var item CapsuleItem
	if err := client.GetDataFromRedis(cm.capsules, cm.capsules.Context(),
		fmt.Sprintf("capsule-%s", did), &item); err != nil {
		return nil, [32]byte{}, errors.Wrap(err, "get capsule error")
	}

	data, err := json.Marshal(item.Capsule)
	if err != nil {
		return nil, [32]byte{}, errors.Wrap(err, "get capsule error")
	}

	return data, cm.pubkey.Encode(), nil
}

func (cm *CryptoModule) EncryptFile(src, target string, acc []byte) (*gosdk.Capsule, error) {
	var pkA [32]byte
	copy(pkA[:], acc[:32])
	st := time.Now()
	capsule, key, err := cm.GenPreKey(pkA)
	if err != nil {
		return nil, errors.Wrap(err, "encrypt file error")
	}
	log.Println("gen pre key time", time.Since(st))
	st = time.Now()
	if err := cm.EncryptFileWithAES(src, target, key); err != nil {
		return nil, errors.Wrap(err, "encrypt file error")
	}
	log.Println("encrypt file with AES time", time.Since(st))
	return capsule, nil
}

func (cm *CryptoModule) DecryptFile(did, src, target string, capsule, rkb, pkX []byte) error {
	//re-encrypt key use gateway pubkey
	newCapsule, err := cm.ReEncryptKey(did, capsule, rkb)
	if err != nil {
		return errors.Wrap(err, "decrypt file error")
	}
	var X [32]byte
	copy(X[:], pkX[:32])
	key, err := cm.DecryptReKey(X, newCapsule)
	if err != nil {
		return errors.Wrap(err, "decrypt file error")
	}
	if err := cm.DecryptFileWithAES(src, target, key); err != nil {
		return errors.Wrap(err, "decrypt file error")
	}
	return nil
}

func (cm *CryptoModule) SaveCapsule(fid string, c *gosdk.Capsule) error {
	item := CapsuleItem{
		Capsule: *c,
		Date:    time.Now(),
	}
	if err := client.PutDataToRedis(cm.capsules, context.Background(), fmt.Sprintf("capsule-%s", fid), item, time.Hour*72); err != nil {
		return errors.Wrap(err, "save capsule error")
	}
	return nil
}

func (cm *CryptoModule) EncryptFileWithAES(src, target string, key []byte) error {
	if err := AesCryptoHandle(
		src, target, key, PLAINTEXT_BLOCK_SIZE, gosdk.AesEncrypt,
	); err != nil {
		return errors.Wrap(err, "encrypt file with AES error")
	}
	return nil
}

func (cm *CryptoModule) DecryptFileWithAES(src, target string, key []byte) error {
	if err := AesCryptoHandle(
		src, target, key, PLAINTEXT_BLOCK_SIZE+16, gosdk.AesDecrypt,
	); err != nil {
		return errors.Wrap(err, "encrypt file with AES error")
	}
	return nil
}

func AesCryptoHandle(src, target string, key []byte, buffSize int,
	handle func(data []byte, key []byte, nonce []byte) ([]byte, error)) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	targetFile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer targetFile.Close()

	for index, flag := 1, false; !flag; index++ {
		buff := make([]byte, buffSize)
		n, err := srcFile.Read(buff)
		if err != nil {
			if strings.Contains(err.Error(), "EOF") {
				break
			}
			return err
		}

		flag = n < buffSize

		hash := sha256.Sum256(fmt.Append([]byte{}, key, index))
		nonce := hash[:12]
		data, err := handle(buff[:n], key, nonce)
		if err != nil {
			return err
		}
		if n, err := targetFile.Write(data); err != nil {
			return err
		} else if n <= 0 {
			return errors.New("empty ciphertext")
		}
	}
	return err
}

func (cm *CryptoModule) GenPreKey(pkA [32]byte) (*gosdk.Capsule, []byte, error) {
	pubkey, err := schnorrkel.NewPublicKey(pkA)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate pre key error")
	}
	capsule, key, err := gosdk.GenPreKey(pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate pre key error")
	}
	return capsule, key, nil
}

func (cm *CryptoModule) ReEncryptKey(did string, capsule, rkb []byte) (*gosdk.Capsule, error) {
	var (
		c   gosdk.Capsule
		rk  *ristretto255.Scalar
		err error
	)
	if len(capsule) <= 0 && did != "" {
		var item CapsuleItem
		if err = client.GetDataFromRedis(cm.capsules, context.Background(),
			fmt.Sprintf("capsule-%s", did), &item); err != nil {
			return nil, errors.Wrap(err, "re-encrypt pre key error")
		}
		c = item.Capsule
	} else if err = json.Unmarshal(capsule, &c); err != nil {
		return nil, errors.Wrap(err, "re-encrypt pre key error")
	}
	rk = ristretto255.NewScalar()
	if err = rk.UnmarshalText(rkb); err != nil {
		return nil, errors.Wrap(err, "re-encrypt pre key error")
	}
	newCapsule, err := gosdk.ReEncryptKey(rk, &c)
	if err != nil {
		return nil, errors.Wrap(err, "re-encrypt pre key error")
	}
	return newCapsule, nil
}

func (cm *CryptoModule) DecryptReKey(pkX [32]byte, newCapsule *gosdk.Capsule) ([]byte, error) {
	pubkeyX, err := schnorrkel.NewPublicKey(pkX)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt pre key error")
	}

	key, err := gosdk.DecryptReKey(cm.sk, newCapsule, pubkeyX)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt pre key error")
	}
	return key, nil
}

// implant for gateway

func (g *Gateway) DecryptData(info *DataInfo, capsule, rkb, pkX []byte, dpath string) error {

	if err := g.cm.DecryptFile(info.Fid, info.Path, dpath, capsule, rkb, pkX); err != nil {
		return errors.Wrap(err, "decrypt data error")
	}
	info.DecryptedFilePath = dpath
	return nil
}

func (g *Gateway) GetCapsule(did string) ([]byte, [32]byte, error) {
	return g.cm.GetCapsule(did)
}

func (g *Gateway) ReEncryptKey(did string, capsule, rkb []byte) ([]byte, error) {
	newCapsule, err := g.cm.ReEncryptKey(did, capsule, rkb)
	if err != nil {
		return nil, errors.Wrap(err, "re-encrypt key error")
	}
	jbytes, err := json.Marshal(newCapsule)
	if err != nil {
		return nil, errors.Wrap(err, "re-encrypt key error")
	}
	return jbytes, nil
}
