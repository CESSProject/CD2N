package node

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain/evm"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/bits-and-blooms/bloom/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

// type StorageNode struct {
// 	Account  string `json:"account"`
// 	Endpoint string `json:"endpoint"`
// }

const (
	MAX_CACHER_NUM = 768
)

type FailureCounter func(string)

func (fc FailureCounter) StatTimes(id string) { fc(id) }

type RetrieverInfo struct {
	Address  string `json:"account"`
	ExtIp    string `json:"ext_ip"`
	Endpoint string `json:"endpoint"`
	Active   bool   `json:"active"`
}

type TokenRecord struct {
	Address  string
	LastTime time.Time
}

type Retriever struct {
	Info         RetrieverInfo      `json:"info"`
	UpdateAt     time.Time          `json:"update_at"`
	StorageNodes *bloom.BloomFilter `json:"storage_nodes"`
	RetrBytes    uint64             `json:"retr_bytes"`
	RetrTimes    uint64             `json:"retr_times"`
	SendTimes    uint64             `json:"send_times"`
	SendBytes    uint64             `json:"send_bytes"`
	AvgSpeed     uint               `json:"avg_speed"`
}

type Cacher struct {
	Account         string                         `json:"account"`
	ExtIp           string                         `json:"ext_ip"`
	StorageNodes    map[string]tsproto.StorageNode `json:"storage_nodes"`
	AccessOn        time.Time                      `json:"access_on"`
	DistTimes       uint64                         `json:"dist_times"`
	DistSucTimes    uint64                         `json:"dist_suc_times"`
	DistFailedTimes uint64                         `json:"dist_failed_times"`
	RetrTimes       uint64                         `json:"retr_times"`
	RetrSucTimes    uint64                         `json:"retr_suc_times"`
}

type NodeManager struct {
	tokenMap                *sync.Map
	contract                *evm.CacheProtoContract
	peerRetrievers          map[string]Retriever
	activeCachers           map[string]Cacher
	activeStorageNodeFilter *bloom.BloomFilter
	activeStorageNodes      *atomic.Int32
	cacherNum               *atomic.Int32
	lock                    *sync.RWMutex
}

func NewNodeManager(contract *evm.CacheProtoContract) *NodeManager {
	return &NodeManager{
		contract:                contract,
		peerRetrievers:          map[string]Retriever{},
		activeCachers:           map[string]Cacher{},
		activeStorageNodes:      &atomic.Int32{},
		cacherNum:               &atomic.Int32{},
		activeStorageNodeFilter: bloom.NewWithEstimates(10000, 0.01),
		lock:                    &sync.RWMutex{},
		tokenMap:                &sync.Map{},
	}
}

func (nm *NodeManager) UpdateCacherToken(token, addr string) {
	nm.tokenMap.Store(token, TokenRecord{
		Address:  addr,
		LastTime: time.Now(),
	})
	nm.tokenMap.Range(func(key, value any) bool {
		if r, ok := value.(TokenRecord); !ok || time.Since(r.LastTime) > 30*time.Minute {
			nm.tokenMap.Delete(key)
		}
		return true
	})
}

func (nm *NodeManager) GetCacherAddr(token string) (string, bool) {
	v, ok := nm.tokenMap.Load(token)
	if !ok {
		return "", false
	}
	r, ok := v.(TokenRecord)
	if !ok || r.Address == "" {
		return "", false
	}
	return r.Address, true
}

func (nm *NodeManager) ExportStorageNodes() []string {
	var nodes []string
	if nm.activeCachers == nil {
		return nodes
	}
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	for _, v := range nm.activeCachers {
		for k := range v.StorageNodes {
			nodes = append(nodes, k)
		}
	}
	return nodes
}

func (nm *NodeManager) LoadCacher(pubkey []byte) (Cacher, bool) {
	key, err := crypto.DecompressPubkey(pubkey)
	if err != nil {
		return Cacher{}, false
	}
	addr := crypto.PubkeyToAddress(*key).Hex()
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	c, ok := nm.activeCachers[addr]
	return c, ok
}

func (nm *NodeManager) LoadRetriever(addr string) (Retriever, bool) {
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	r, ok := nm.peerRetrievers[addr]
	return r, ok
}

func (nm *NodeManager) LoadAllRetrievers(limit int) []Retriever {
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	if limit <= 0 || limit > len(nm.peerRetrievers) {
		limit = len(nm.peerRetrievers)
	}
	retrievers := make([]Retriever, 0, limit)
	for _, v := range nm.peerRetrievers {
		retrievers = append(retrievers, v)
	}
	return retrievers
}

func (nm *NodeManager) SaveOrUpdateRetriever(info RetrieverInfo, storageNodes []string) {
	if len(storageNodes) <= 0 || info.Address == "" || info.Endpoint == "" {
		return
	}
	filter := bloom.NewWithEstimates(uint(len(storageNodes)*3/2), 0.01)
	for _, acc := range storageNodes {
		pk, err := utils.ParsingPublickey(acc)
		if err != nil || len(pk) <= 0 {
			continue
		}
		filter.Add(pk)
	}
	nm.lock.Lock()
	defer nm.lock.Unlock()
	retriever := nm.peerRetrievers[info.Address]
	retriever.Info = info
	retriever.StorageNodes = filter
	retriever.UpdateAt = time.Now()
	nm.peerRetrievers[info.Address] = retriever
}

func (nm *NodeManager) updateCachers() {
	nm.lock.Lock()
	defer nm.lock.Unlock()
	for key, cacher := range nm.activeCachers {
		if cacher.DistFailedTimes*100/(cacher.DistTimes+1) >= 60 {
			delete(nm.activeCachers, key)
			nm.activeStorageNodes.Add(-int32(len(cacher.StorageNodes)))
		}
	}
}

func (nm *NodeManager) SavedCacher(addr string) bool {
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	_, ok := nm.activeCachers[addr]
	return ok
}

func (nm *NodeManager) SaveOrUpdateCacher(pubkey []byte, extIp string, storageNodes []tsproto.StorageNode) error {
	nm.updateCachers()

	if len(pubkey) == 0 || extIp == "" {
		return nil
	}

	key, err := crypto.DecompressPubkey(pubkey)
	if err != nil {
		return errors.Wrap(err, "save or update cacher error")
	}
	addr := crypto.PubkeyToAddress(*key).Hex()

	if !nm.SavedCacher(addr) && nm.cacherNum.Load() >= MAX_CACHER_NUM {
		return errors.Wrap(errors.New("cacher queue is full"), "save or update cacher error")
	}

	nodes := make(map[string]tsproto.StorageNode)
	for _, node := range storageNodes {
		nodes[node.Account] = node
		pk, err := utils.ParsingPublickey(node.Account)
		if err == nil && len(pk) > 0 {
			nm.activeStorageNodeFilter.Add(pk)
		}
	}

	nm.activeStorageNodes.Add(int32(len(nodes)))

	nm.lock.Lock()
	defer nm.lock.Unlock()

	cacher := nm.activeCachers[addr]
	nm.activeStorageNodes.Add(-int32(len(cacher.StorageNodes)))
	cacher.Account = addr
	cacher.ExtIp = extIp
	cacher.StorageNodes = nodes
	cacher.AccessOn = time.Now()
	nm.activeCachers[addr] = cacher
	return nil
}

func (nm *NodeManager) CacherDistribution(addr string, success bool) {

	nm.lock.Lock()
	defer nm.lock.Unlock()
	cacher, ok := nm.activeCachers[addr]
	if !ok {
		return
	}
	if success {
		cacher.DistSucTimes++
	} else {
		cacher.DistTimes++
	}
	nm.activeCachers[addr] = cacher
}

func (nm *NodeManager) CacherDistFailed(addr string) {
	nm.lock.Lock()
	defer nm.lock.Unlock()
	cacher, ok := nm.activeCachers[addr]
	if !ok {
		return
	}
	cacher.DistFailedTimes++
	nm.activeCachers[addr] = cacher
}

func (nm *NodeManager) CacherRetrieval(addr string, success bool) {

	nm.lock.Lock()
	defer nm.lock.Unlock()
	cacher, ok := nm.activeCachers[addr]
	if !ok {
		return
	}
	if success {
		cacher.RetrSucTimes++
	} else {
		cacher.RetrTimes++
	}
	nm.activeCachers[addr] = cacher
}

func (nm *NodeManager) RetrieverSend(addr string, bytes uint64) {

	nm.lock.Lock()
	defer nm.lock.Unlock()
	retriever, ok := nm.peerRetrievers[addr]
	if !ok {
		return
	}
	retriever.SendBytes = bytes
	retriever.SendTimes++
	nm.peerRetrievers[addr] = retriever
}

func (nm *NodeManager) RetrieverReceive(addr string, bytes uint64) {

	nm.lock.Lock()
	defer nm.lock.Unlock()
	retriever, ok := nm.peerRetrievers[addr]
	if !ok {
		return
	}
	retriever.RetrBytes = bytes
	retriever.RetrTimes++
	nm.peerRetrievers[addr] = retriever
}

func (nm *NodeManager) LocatingResources(storageNodes []string) (Retriever, bool) {
	var (
		count int
		cmap  map[string]int = make(map[string]int)
	)
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	for _, node := range storageNodes {
		pk, err := utils.ParsingPublickey(node)
		if err != nil || len(pk) <= 0 {
			continue
		}
		if nm.activeStorageNodeFilter != nil && nm.activeStorageNodeFilter.Test(pk) {
			count++
			if count >= 4 {
				return Retriever{}, true
			}
		}
		for k, v := range nm.peerRetrievers {
			if v.StorageNodes != nil && v.StorageNodes.Test(pk) {
				c := cmap[k]
				c++
				if c >= 4 {
					return v, true
				}
				cmap[k] = c
			}
		}
	}
	return Retriever{}, false
}

func (nm *NodeManager) QueryRetrieverInfo(addr string) (evm.NodeInfo, error) {
	info, err := nm.contract.QueryRegisterInfo(common.HexToAddress(addr))
	return info, errors.Wrap(err, "query retriever info error")
}

func (nm *NodeManager) DiscoveryRetrievers() error {
	conf := config.GetConfig()
	cli, err := chain.NewLightCessClient("", conf.Rpcs)
	if err != nil {
		return errors.Wrap(err, "discovery retrievers error")
	}
	// load oss nodes on chain
	osses, err := cli.QueryAllOss(0)
	if err == nil {
		for _, oss := range osses {
			endpoint := string(oss.Domain)
			if endpoint == "" || endpoint == conf.Endpoint {
				continue
			}
			if !strings.Contains(endpoint, "http://") && !strings.Contains(endpoint, "https://") {
				endpoint = fmt.Sprintf("http://%s", endpoint)
			}
			data, err := tsproto.CheckCdnNodeAvailable(endpoint)
			if err != nil {
				continue
			}
			if data.WorkAddr == "" {
				data.WorkAddr = hex.EncodeToString(oss.Domain)
			}

			nm.SaveOrUpdateRetriever(RetrieverInfo{
				Address:  data.WorkAddr,
				Endpoint: endpoint,
				Active:   true,
			}, data.ActiveStorageNodes)
			log.Println("save or update retriever:", data.WorkAddr, data.EndPoint)
		}
	}
	// load oss nodes in cache protocol smart contract
	var (
		index int64
		addr  common.Address
	)
	for {
		addr, err = nm.contract.QueryCdnL1NodeByIndex(index)
		if err != nil {
			break
		}
		index++
		info, err := nm.contract.QueryRegisterInfo(addr)
		if err != nil || addr.Cmp(nm.contract.Node) == 0 {
			continue
		}
		data, err := tsproto.CheckCdnNodeAvailable(info.Endpoint)
		if err != nil {
			continue
		}
		nm.SaveOrUpdateRetriever(RetrieverInfo{
			Address:  data.WorkAddr,
			Endpoint: info.Endpoint,
			Active:   true,
		}, data.ActiveStorageNodes)
	}
	return nil
}
