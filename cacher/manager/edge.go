package manager

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/CD2N/CD2N/cacher/config"
	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/cache"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

type OffloadingTaskExecutor struct {
	pool       *ants.Pool
	tempDir    string
	privateKey *ecdsa.PrivateKey
	dataCache  *cache.Cache
	*StoragersManager
}

func NewOffloadingTaskExecutor(sk string, c *cache.Cache, tempDir string, sm *StoragersManager) (*OffloadingTaskExecutor, error) {
	priKey, err := crypto.HexToECDSA(sk)
	if err != nil {
		return nil, errors.Wrap(err, "new offloading task executor error")
	}
	pool, err := ants.NewPool(16, ants.WithNonblocking(true))
	if err != nil {
		return nil, errors.Wrap(err, "new cess access task executor error")
	}
	return &OffloadingTaskExecutor{
		pool:             pool,
		tempDir:          tempDir,
		privateKey:       priKey,
		dataCache:        c,
		StoragersManager: sm,
	}, nil
}

func (te *OffloadingTaskExecutor) ClaimDataFromRetriever(task Task) error {
	req := tsproto.FileRequest{
		Pubkey:    crypto.CompressPubkey(&te.privateKey.PublicKey),
		Timestamp: time.Now().Format(TIME_LAYOUT),
	}
	jbytes, _ := json.Marshal(&req)
	sign, _ := utils.SignWithSecp256k1PrivateKey(te.privateKey, jbytes)
	req.Sign = hex.EncodeToString(sign)
	u, err := url.JoinPath(task.Addr, tsproto.CLAIM_DATA_URL)
	if err != nil {
		return errors.Wrap(err, "cliam offloading data from gateway error")
	}
	data, did, err := tsproto.ClaimOffloadingData(u, req)
	if err != nil {
		return errors.Wrap(err, "cliam offloading data from gateway error")
	}
	if strings.Trim(did, " ") == "" {
		return errors.Wrap(err, "cliam offloading data from gateway error")
	}
	f, err := os.Create(path.Join(te.tempDir, did))
	if err != nil {
		return errors.Wrap(err, "cliam offloading data from gateway error")
	}
	defer f.Close()
	if n, err := f.Write(data); err != nil {
		return errors.Wrap(err, "cliam offloading data from gateway error")
	} else {
		te.dataCache.AddWithData(task.Did, path.Join(te.tempDir, did), int64(n))
	}

	logger.GetLogger(config.LOG_TASK).Infof("task[%s]: claim offloading data %s success", task.Tid, did)
	return nil
}

func (te *OffloadingTaskExecutor) Execute(task Task) error {

	stat := te.dataCache.Status()
	if te.GetStoragerNumber() >= 12 || stat.Usage >= 0.9 {
		return nil
	}

	te.pool.Submit(func() {
		if err := te.ClaimDataFromRetriever(task); err != nil {
			logger.GetLogger(config.LOG_TASK).Error("failed to process data offloading task", err)
		}
	})
	return nil
}
