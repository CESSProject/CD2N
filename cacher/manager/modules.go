package manager

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/cacher/client"
	"github.com/CD2N/CD2N/cacher/config"
	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CESSProject/go-sdk/chain"
	"github.com/CESSProject/go-sdk/chain/evm"
	"github.com/CESSProject/go-sdk/libs/tsproto"
	"github.com/CESSProject/go-sdk/logger"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	ecies "github.com/ecies/go/v2"
	"github.com/go-redis/redis/v8"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

type RetrieverProvider interface {
	GetRetriever(key string) (Retriever, bool)
	ErrorFeedback(key string)
}

// type StoragerProvider interface {
// }

type Storager struct {
	Account    string `json:"account"`
	TotalSpace uint64 `json:"total_space"`
	UsedSpace  uint64 `json:"used_space"`
	Endpoint   string `json:"endpoint"`
	Available  bool   `json:"available"`
}

func (n *Storager) IsAvailable() bool {
	return n.Available
}

type Retriever struct {
	Account      string        `json:"account"`
	Endpoint     string        `json:"endpoint"`
	RedisAddress string        `json:"redis_address"`
	TeePubkey    []byte        `json:"tee_pubkey"`
	IsGateway    bool          `json:"is_gateway"`
	redisCli     *redis.Client `json:"-"`
	unsubCh      chan struct{} `json:"-"`
	subscribing  *atomic.Bool  `json:"-"`
	Available    bool          `json:"available"`
	ErrorCount   int           `json:"error_count"`
}

func (n *Retriever) IsAvailable() bool {
	return n.Available
}

func (n *Retriever) SubscribeMessage(ctx context.Context, receiver chan<- *redis.Message, channel ...string) {

	if n.subscribing == nil {
		n.subscribing = &atomic.Bool{}
	}
	if n.redisCli == nil || n.subscribing.Load() || !n.subscribing.CompareAndSwap(false, true) {
		logger.GetLogger(config.LOG_NODE).Error("subscribe error ", n.redisCli, " ", n.subscribing.Load())
		return
	}
	sub := n.redisCli.Subscribe(ctx, channel...)
	defer sub.Close()
	ch := sub.Channel()
	logger.GetLogger(config.LOG_NODE).Info("subscribe to ", n.Endpoint)
	for {
		select {
		case <-n.unsubCh:
			n.subscribing.Store(false)
			return
		case <-ctx.Done():
			n.subscribing.Store(false)
			return
		case msg, open := <-ch:
			receiver <- msg
			if !open {
				n.subscribing.Store(false)
				return
			}
		}
	}
}

///////////*******************************/////////////

type StoragersManager struct {
	lock      *sync.RWMutex
	storagers []Storager
	num       *atomic.Uint32
	smap      map[string]int
	index     int
}

func NewStoragersManager() *StoragersManager {
	return &StoragersManager{
		lock: &sync.RWMutex{},
		num:  &atomic.Uint32{},
		smap: make(map[string]int),
	}
}

func (sm *StoragersManager) GetStoragerNumber() int {
	return int(sm.num.Load())
}

func (sm *StoragersManager) GetStorager(minerAcc string) (Storager, bool) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	if idx, ok := sm.smap[minerAcc]; ok {
		if idx >= 0 && idx < len(sm.storagers) {
			return sm.storagers[idx], true
		}
	}
	for _, storager := range sm.storagers {
		if storager.Account == minerAcc {
			return storager, true
		}
	}
	return Storager{}, false
}

func (sm *StoragersManager) ExportStorages() []tsproto.StorageNode {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	storagers := make([]tsproto.StorageNode, 0, len(sm.storagers))
	for _, storager := range sm.storagers {
		storagers = append(storagers, tsproto.StorageNode{
			Account:  storager.Account,
			Endpoint: storager.Endpoint,
		})
	}
	sm.num.Store(uint32(len(storagers)))
	return storagers
}

func (sm *StoragersManager) GetMinerEndpoint(dCount uint64) (tsproto.StorageNode, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	var ep tsproto.StorageNode
	if len(sm.storagers) == 0 {
		return ep, errors.Wrap(errors.New("no nodes available"), "get miner endpoint error")
	}

	if sm.index < 0 || sm.index > len(sm.storagers) {
		return ep, errors.Wrap(errors.New("node not found"), "get miner endpoint error")
	}
	target := sm.storagers[sm.index]
	if target.Account == "" || target.Endpoint == "" {
		return ep, errors.Wrap(errors.New("no legal storage node"), "get miner endpoint error")
	}
	ep.Account = target.Account
	ep.Endpoint = target.Endpoint
	logger.GetLogger(config.LOG_TASK).Infof("selected miner %s, index:%d, total miners %d", ep.Account, sm.index, len(sm.storagers))
	sm.index = (sm.index + 1) % len(sm.storagers)
	return ep, nil
}

func (sm *StoragersManager) LoadStorageNodes(conf config.Config) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	var miners config.MinerConfig

	err := config.LoadGeneralConfig(conf.MinerConfigPath, &miners)
	logger.GetLogger(config.LOG_NODE).Info("load storage nodes from ", conf.MinerConfigPath)
	if err != nil {
		return err
	}
	chainCli, err := chain.NewLightCessClient("", conf.Rpcs)
	if err != nil {
		return errors.Wrap(err, "load storage nodes error")
	}
	defer chainCli.Client.Close()
	for _, miner := range conf.StorageNodes {
		acc, err := utils.ParsingPublickey(miner.Account)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		node := Storager{
			Account:  miner.Account,
			Endpoint: miner.Endpoint,
		}
		info, err := chainCli.QueryMinerItems(acc, 0)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		node.TotalSpace = uint64(info.IdleSpace.Int64())
		node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
		node.Available = CheckNodeAvailable(&node)
		sm.storagers = append(sm.storagers, node)
		sm.smap[miner.Account] = len(sm.storagers) - 1
	}

	logger.GetLogger(config.LOG_NODE).Infof("load %d miners from miner config file", len(miners.Miners))

	for _, miner := range miners.Miners {
		endpoint := fmt.Sprintf("http://127.0.0.1:%d", miner.Port)
		keyring, err := signature.KeyringPairFromSecret(miner.Mnemonic, 0)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		acc := utils.EncodePubkey(keyring.PublicKey, conf.Network)
		if _, ok := sm.smap[acc]; ok {
			continue
		}
		node := Storager{
			Account:  acc,
			Endpoint: endpoint,
		}
		info, err := chainCli.QueryMinerItems(keyring.PublicKey, 0)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		node.TotalSpace = uint64(info.IdleSpace.Int64())
		node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
		node.Available = CheckNodeAvailable(&node)
		logger.GetLogger(config.LOG_NODE).Info("load storage ", node.Account, " available? ", node.Available)
		sm.storagers = append(sm.storagers, node)
		sm.smap[acc] = len(sm.storagers) - 1
	}
	return nil
}

func (sm *StoragersManager) UpdateStorageNodeStatus(ctx context.Context, conf config.Config) error {
	ticker := time.NewTicker(time.Minute * 60)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			chainCli, err := chain.NewLightCessClient("", conf.Rpcs)
			if err != nil {
				logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
				continue
			}
			sm.lock.Lock()
			for i, node := range sm.storagers {
				acc, err := utils.ParsingPublickey(node.Account)
				if err != nil {
					logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
					continue
				}
				info, err := chainCli.QueryMinerItems(acc, 0)
				if err != nil {
					logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
					continue
				}
				node.TotalSpace = uint64(info.IdleSpace.Int64())
				node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
				node.Available = CheckNodeAvailable(&node)
				sm.storagers[i] = node
			}
			sm.lock.Unlock()
			chainCli.Client.Close()
		}
	}
}

type RetrieverManager struct {
	nodes *sync.Map
}

func NewRetrieverManager() *RetrieverManager {
	return &RetrieverManager{
		nodes: &sync.Map{},
	}
}

func (rm *RetrieverManager) GetRetriever(key string) (Retriever, bool) {
	v, ok := rm.nodes.Load(key)
	if !ok {
		return Retriever{}, ok
	}
	node, ok := v.(*Retriever)
	if !ok {
		return Retriever{}, ok
	}
	if !node.Available {
		return Retriever{}, false
	}
	return *node, true
}

func (rm *RetrieverManager) ErrorFeedback(key string) {
	v, ok := rm.nodes.Load(key)
	if !ok {
		return
	}
	node, ok := v.(*Retriever)
	if !ok {
		return
	}
	node.ErrorCount++
	if node.ErrorCount >= 2000 {
		node.Available = false
		select {
		case node.unsubCh <- struct{}{}:
		default:
		}
	}
}

func (rm *RetrieverManager) SubscribeRetrievers(ctx context.Context, receiver chan<- *redis.Message, channel ...string) {
	rm.nodes.Range(func(key, value any) bool {
		node, ok := value.(*Retriever)
		if !ok {
			return true
		}
		if node.Available {
			ants.Submit(func() {
				node.SubscribeMessage(ctx, receiver, channel...)
			})
		}
		return true
	})
}

func (rm *RetrieverManager) LoadRetrievers(cli *evm.CacheProtoContract, conf config.Config, redisAcc, redisPwd string) error {
	for _, cdn := range conf.Retrievers {
		if cdn.Account == "" || cdn.Endpoint == "" {
			continue
		}

		if actl, ok := rm.nodes.Load(cdn.Account); ok {
			if old, ok := actl.(*Retriever); ok && !old.Available {
				old.Endpoint = cdn.Endpoint
				old.Available = CheckNodeAvailable(old)
			}
		} else {
			node := &Retriever{
				Account:  cdn.Account,
				Endpoint: cdn.Endpoint,
				unsubCh:  make(chan struct{}, 1),
			}

			if node.Available = CheckNodeAvailable(node); node.Available {
				node.redisCli = client.NewRedisClient(node.RedisAddress, redisAcc, redisPwd)
				rm.nodes.Store(cdn.Account, node)
			}
			logger.GetLogger(config.LOG_NODE).Infof("load retriever %s in local config", cdn.Endpoint)
		}
	}
	var index int64
	//load retriever node on contract
	for {
		addr, err := cli.QueryCdnL1NodeByIndex(index)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error("query cdn node info error ", err.Error())
			break
		}
		index++
		info, err := cli.QueryRegisterInfo(addr)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error("query cdn node info error ", err.Error())
			continue
		}
		account := addr.Hex()
		if actl, ok := rm.nodes.Load(account); ok {
			if old, ok := actl.(*Retriever); ok && !old.Available {
				old.Endpoint = info.Endpoint
				old.Available = CheckNodeAvailable(old)
			}
		} else {
			node := &Retriever{
				Account:  account,
				Endpoint: info.Endpoint,
				unsubCh:  make(chan struct{}, 1),
			}
			if node.Available = CheckNodeAvailable(node); node.Available {
				node.redisCli = client.NewRedisClient(node.RedisAddress, redisAcc, redisPwd)
				rm.nodes.Store(account, node)
			}
			logger.GetLogger(config.LOG_NODE).Infof("load retriever %s on contract", info.Endpoint)
		}
	}

	//load retriever node on chain
	chainCli, err := chain.NewLightCessClient("", config.GetConfig().Rpcs)
	if err != nil {
		return errors.Wrap(err, "load retrievers error")
	}
	osses, err := chainCli.QueryAllOss(0)
	if err != nil {
		return errors.Wrap(err, "load oss nodes error")
	}
	for _, oss := range osses {
		node := &Retriever{
			Endpoint: string(oss.Domain),
		}
		if node.Endpoint == "" {
			continue
		}
		if !strings.Contains(node.Endpoint, "http://") && !strings.Contains(node.Endpoint, "https://") {
			node.Endpoint = fmt.Sprintf("http://%s", node.Endpoint)
		}
		if node.Available = CheckNodeAvailable(node); !node.Available {
			continue
		}
		if actl, ok := rm.nodes.Load(node.Account); ok {
			if old, ok := actl.(*Retriever); ok && !old.Available {
				old.Endpoint = node.Endpoint
				old.Available = node.Available
			}
		} else {
			node.unsubCh = make(chan struct{}, 1)
			node.redisCli = client.NewRedisClient(node.RedisAddress, redisAcc, redisPwd)
			rm.nodes.Store(node.Account, node)
			logger.GetLogger(config.LOG_NODE).Infof("load oss %s on chain", oss.Domain)
		}
	}
	return nil
}

func CheckNodeAvailable(node any) bool {
	switch n := node.(type) {
	case *Storager:
		return tsproto.CheckStorageNodeAvailable(n.Endpoint) == nil
	case *Retriever:
		info, err := tsproto.CheckCdnNodeAvailable(n.Endpoint)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error("check cdn node available error ", err.Error())
			return false
		}
		if n.Account == "" {
			n.Account = info.WorkAddr
		}
		n.ErrorCount = 0
		n.TeePubkey = info.TeePubkey
		n.IsGateway = info.IsGateway
		n.RedisAddress = info.RedisAddr
	}
	return true
}

// //////////////////////////////

type SignTool interface {
	SignMsg(msg string) (string, error)
	UpdateSign(msg string) error
	GetSignInfoTuple() (acc, msg, sign string)
}

type CessSignTool struct {
	message string
	account string
	sign    string
	keypair signature.KeyringPair
}

func NewCessSignTool() (*CessSignTool, error) {
	msg := utils.GetRandomcode(16)
	mnemonic, err := utils.GenerateMnemonic()
	if err != nil {
		return nil, errors.Wrap(err, "new cess sign tool error")
	}
	keypair, err := signature.KeyringPairFromSecret(mnemonic, 0)
	if err != nil {
		return nil, errors.Wrap(err, "new cess sign tool error")
	}

	acc := utils.EncodePubkey(keypair.PublicKey, config.GetConfig().Network)

	sign, err := utils.SignedSR25519WithMnemonic(keypair.URI, msg)
	if err != nil {
		return nil, errors.Wrap(err, "new file manager error")
	}
	return &CessSignTool{
		message: msg,
		account: acc,
		sign:    hex.EncodeToString(sign),
	}, nil
}

func (ct *CessSignTool) SignMsg(msg string) (string, error) {
	sign, err := utils.SignedSR25519WithMnemonic(ct.keypair.URI, msg)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign message")
	}
	return hex.EncodeToString(sign), nil
}

func (ct *CessSignTool) UpdateSign(msg string) error {
	msg, err := ct.SignMsg(msg)
	if err != nil {
		return errors.Wrap(err, "update sign error")
	}
	ct.message = msg
	return nil
}

func (ct *CessSignTool) GetSignInfoTuple() (acc, msg, sign string) {
	return ct.account, ct.message, ct.sign
}

///////////////////////////////////////////

type AesKeyProvider interface {
	GetAESKey(pubkey []byte) ([]byte, []byte, error)
}

type EcdhAesKeyManager struct {
	Key  *ecies.PrivateKey
	Date time.Time
}

func (em *EcdhAesKeyManager) GetAESKey(pubkey []byte) ([]byte, []byte, error) {
	var err error

	if em.Key == nil || time.Since(em.Date) > time.Hour*24*7 {
		em.Key, err = ecies.GenerateKey()
		if err != nil {
			return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
		}
		em.Date = time.Now()
	}
	pk, err := ecies.NewPublicKeyFromBytes(pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}

	key, err := em.Key.ECDH(pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}
	return key, em.Key.PublicKey.Bytes(true), nil
}
