package handles

import (
	"context"
	"encoding/hex"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/gateway"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/node"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain/evm"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/decred/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/vedhavyas/go-subkey"
	"golang.org/x/crypto/blake2b"
)

type ServerHandle struct {
	retr        *node.ResourceRetriever
	node        *node.Manager
	partners    *node.NodeManager
	gateway     *gateway.Gateway
	buffer      *buffer.FileBuffer
	Ac          *AccessController
	partRecord  *redis.Client //*leveldb.DB
	filepartMap *sync.Map
	ossPubkey   []byte
	teeEndpoint string
	teePubkey   []byte
	teeAddr     string
	nodeAddr    string
	poolId      string
}

type PartsInfo struct {
	ShadowHash string    `json:"shadow_hash,omitempty"`
	FileName   string    `json:"file_name,omitempty"`
	DirName    string    `json:"dir_name,omitempty"`
	Archive    string    `json:"archive,omitempty"`
	Owner      []byte    `json:"owner,omitempty"`
	Territory  string    `json:"territory,omitempty"`
	Parts      []string  `json:"parts,omitempty"`
	PartsCount int       `json:"parts_count,omitempty"`
	TotalParts int       `json:"total_parts,omitempty"`
	TotalSize  int64     `json:"total_size,omitempty"`
	UpdateDate time.Time `json:"update_date,omitempty"`
}

func NewServerHandle() *ServerHandle {
	return &ServerHandle{
		filepartMap: &sync.Map{},
	}
}

func (h *ServerHandle) InitHandlesRuntime(ctx context.Context) error {
	conf := config.GetConfig()
	if conf.PoolName == "" {
		conf.PoolName = config.DEFAULT_CD2N_POOLID
	}
	h.poolId = base58.Encode([]byte(conf.PoolName))

	if !conf.Debug {
		h.teeEndpoint = conf.TeeAddress
		u, err := url.JoinPath(h.teeEndpoint, tsproto.QUERY_TEE_INFO)
		if err != nil {
			return errors.Wrap(err, "init handles runtime error")
		}
		var data tsproto.TeeResp
		for range 5 {
			data, err = tsproto.QueryTeeInfo(u)
			if err == nil && data.EthAddress != "" {
				break
			}
			time.Sleep(time.Second * 6)
		}
		if err != nil {
			return errors.Wrap(err, "init handles runtime error")
		}
		h.teeAddr = data.EthAddress
		h.teePubkey = data.Pubkey
		go func() {
			ticker := time.NewTicker(time.Hour * 24 * 25)
			for {
				err := h.RechargeGasFeeForTEE(h.teeAddr, conf)
				if err != nil {
					log.Println(err)
					time.Sleep(time.Minute * 15)
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	} else {
		h.teeEndpoint = "http://139.180.142.180:1309"
	}

	// build workspace
	if err := BuildWorkspace(conf.WorkSpace); err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	// // init level databases
	// log.Println("init level databases ...")
	// if err := client.RegisterLeveldbCli(
	// 	filepath.Join(conf.WorkSpace, config.LEVELDB_DIR), config.TASKDB_NAME,
	// ); err != nil {
	// 	return errors.Wrap(err, "init handles runtime error")
	// }
	// register nodes
	log.Println("register nodes ...")
	contractCli, err := h.registerNode(conf)
	if err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	log.Println("init cd2n base module(redis client) ...")
	redisCli := client.NewRedisClient(conf.RedisLoacl, "retriever", conf.RedisPwd)
	h.partRecord = redisCli
	h.nodeAddr = contractCli.Node.Hex()

	h.buffer, err = buffer.NewFileBuffer(
		uint64(conf.FileBufferSize),
		filepath.Join(conf.WorkSpace, config.DATA_BUFFER_DIR),
	)
	if err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	// init nodes
	log.Println("init retriever node ...")
	h.node = node.NewManager(
		redisCli, h.buffer, contractCli.Node.Hex(), h.teeEndpoint,
	)
	h.partners = node.NewNodeManager(contractCli)

	go func() {
		ticker := time.NewTicker(time.Minute * 30)
		if err := h.partners.DiscoveryRetrievers(); err != nil {
			log.Println(err)
		}
		count := 0
		for range ticker.C {
			if err = h.partners.DiscoveryRetrievers(); err != nil {
				count++
				if count%48 == 0 { //print error log per 6 hours
					log.Println(err)
					count = 0
				}
			}
		}
	}()

	h.retr, err = node.NewResourceRetriever(
		512, contractCli.Node.Hex(), h.partners,
		h.buffer, h.node, contractCli.Signature,
	)

	if err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	go h.node.CallbackManager(ctx)

	fileCacher, err := buffer.NewFileBuffer(
		uint64(conf.GatewayCacheSize),
		filepath.Join(conf.WorkSpace, config.FILE_CACHE_DIR),
	)
	if err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	h.Ac = NewAccessController(time.Minute, h.buffer, fileCacher)

	if !conf.LaunchGateway {
		return nil
	}

	// init gateway, if it be needed
	log.Println("init gateway model ...")
	if h.gateway, err = gateway.NewGateway(
		redisCli, contractCli, fileCacher,
		// 	client.GetLeveldbCli(config.TASKDB_NAME),
	); err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	//register oss node on chain
	log.Println("check or register oss node on chain ...")
	if err = h.registerOssNode(conf); err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	go func() {
		err := h.gateway.ProvideTaskChecker(ctx, h.buffer, node.FailureCounter(h.partners.CacherDistFailed))
		if err != nil {
			log.Fatal("run providing task checker error", err)
		}
	}()

	go func() {
		err := h.AsyncUploadFiles(ctx)
		if err != nil {
			log.Fatal("run providing task checker error", err)
		}
	}()
	return nil
}

func ConvertPubkey(addr string) []byte {
	bytesAddr := common.HexToAddress(addr).Bytes()
	data := append([]byte("evm:"), bytesAddr...)
	hashed := blake2b.Sum256(data)
	return hashed[:]
}

func (h *ServerHandle) RechargeGasFeeForTEE(addr string, conf config.Config) error {
	hashed := ConvertPubkey(addr)
	cessAcc := subkey.SS58Encode(hashed[:], uint16(conf.ChainId))
	cli, err := chain.NewLightCessClient(conf.Mnemonic, conf.Rpcs)
	if err != nil {
		return errors.Wrap(err, "check and transfer gas free error")
	}
	account, err := utils.ParsingPublickey(cessAcc)
	if err != nil {
		return errors.Wrap(err, "check and transfer gas free error")
	}
	info, err := cli.QueryAccountInfo(account, 0)
	if err != nil {
		return errors.Wrap(err, "check and transfer gas free error")
	}
	flag, _ := big.NewInt(0).SetString("1000000000000000000000", 10)
	if info.Data.Free.Cmp(flag) >= 0 {
		return nil
	}
	_, err = cli.TransferToken(cessAcc, "1000000000000000000000", nil, nil)
	if err != nil {
		return errors.Wrap(err, "check and transfer gas free error")
	}
	return nil
}

func (h *ServerHandle) registerOssNode(conf config.Config) error {
	cli, err := h.gateway.GetCessClient()
	if err != nil {
		return errors.Wrap(err, "register OSS node on chain error")
	}
	key := cli.GetKeyInOrder()
	h.ossPubkey = key.PublicKey
	oss, err := cli.QueryOss(key.PublicKey, 0)
	cli.PutKey(key.Address)
	if err == nil {
		log.Println("already reigster oss :", string(oss.Domain))
		return nil
	}
	log.Println("query oss info error:", err)
	hash, err := cli.RegisterOss(conf.Endpoint, nil, nil)
	if err != nil {
		return errors.Wrap(err, "register OSS node on chain error")
	}
	log.Println("register OSS node success, tx hash:", hash)
	return nil
}

func (h *ServerHandle) registerNode(conf config.Config) (*evm.CacheProtoContract, error) {
	cli, err := evm.NewClient(
		evm.AccountPrivateKey(conf.SecretKey),
		evm.ChainID(conf.ChainId),
		evm.ConnectionRpcAddresss(conf.Rpcs),
		evm.EthereumGas(conf.GasFreeCap, conf.GasLimit),
	)
	if err != nil {
		return nil, errors.Wrap(err, "register node error")
	}

	contract, err := evm.NewProtoContract(
		cli.GetEthClient(),
		conf.ProtoContract,
		conf.SecretKey,
		cli.NewTransactionOption,
		cli.SubscribeFilterLogs,
	)
	if err != nil {
		return nil, errors.Wrap(err, "register node error")
	}
	if conf.Debug {
		return contract, nil
	}
	info, err := contract.QueryRegisterInfo(cli.Account)
	if err == nil && len(info.TeeEth.Bytes()) > 0 {
		return contract, nil
	}
	sign, err := hex.DecodeString(conf.TokenAccSign)
	if err != nil {
		return nil, errors.Wrap(err, "register node error")
	}
	if err = contract.RegisterNode(context.Background(), evm.RegisterReq{
		NodeAcc:   cli.Account,
		TokenAcc:  common.HexToAddress(conf.TokenAcc),
		Endpoint:  conf.Endpoint,
		TokenId:   conf.Token,
		Signature: sign,
		TeeEth:    common.HexToAddress(h.teeAddr),
		TeeCess:   h.teePubkey,
	}); err != nil {
		return nil, errors.Wrap(err, "register node error")
	}

	return contract, nil
}

func BuildWorkspace(workspace string) error {

	if _, err := os.Stat(workspace); err != nil {
		if err = os.MkdirAll(workspace, 0755); err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}
	cacheDir := filepath.Join(workspace, config.FILE_CACHE_DIR)
	if _, err := os.Stat(cacheDir); err != nil {
		if err = os.Mkdir(cacheDir, 0755); err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}

	bufferDir := filepath.Join(workspace, config.DATA_BUFFER_DIR)
	if _, err := os.Stat(bufferDir); err != nil {
		if err = os.Mkdir(bufferDir, 0755); err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}

	dbDir := filepath.Join(workspace, config.LEVELDB_DIR)
	if _, err := os.Stat(dbDir); err != nil {
		if err = os.Mkdir(dbDir, 0755); err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}
	return nil
}

func (h *ServerHandle) GetNodeInfo(c *gin.Context) {
	conf := config.GetConfig()
	gatewayStatus := h.gateway.GatewayStatus()
	cacheStatus := h.gateway.FileCacher.BufferStatus()
	bufferStatus := h.buffer.BufferStatus()
	nodeStatus := h.node.NodeStatus()
	c.JSON(http.StatusOK,
		tsproto.NewResponse(http.StatusOK, "succes", tsproto.Cd2nNode{
			WorkAddr:           h.node.GetNodeAddress(),
			TeeAddr:            h.teeAddr,
			TeePubkey:          h.teePubkey,
			IsGateway:          h.gateway != nil,
			PoolId:             h.poolId,
			EndPoint:           conf.Endpoint,
			RedisAddr:          conf.RedisAddress,
			ActiveStorageNodes: h.retr.ExportStorageNodes(),
			Status: tsproto.Status{
				DiskStatus: tsproto.DiskStatus{
					UsedCacheSize:  cacheStatus.UsedSize,
					CacheItemNum:   cacheStatus.ItemNum,
					CacheUsage:     cacheStatus.Usage,
					UsedBufferSize: bufferStatus.UsedSize,
					BufferItemNum:  bufferStatus.ItemNum,
					BufferUsage:    bufferStatus.Usage,
				},
				DistStatus: tsproto.DistStatus{
					Ongoing: gatewayStatus.Ongoing,
					Done:    gatewayStatus.Done,
					Retried: gatewayStatus.Retried,
					FidNum:  gatewayStatus.FidNum,
				},
				RetrieveStatus: tsproto.RetrieveStatus{
					NTBR:         nodeStatus.NTBR,
					RetrieveNum:  nodeStatus.RetrieveNum,
					RetrievedNum: nodeStatus.RetrievedNum,
				},
				DownloadStatus: tsproto.DownloadStatus{
					DlingNum: gatewayStatus.DlingNum,
				},
			},
		}))
}

func (h *ServerHandle) GetPreCapsule(c *gin.Context) {
	fid := c.Param("fid")
	capsule, pubkey, err := h.gateway.GetCapsule(fid)
	if err != nil {
		c.JSON(http.StatusBadRequest,
			tsproto.NewResponse(http.StatusBadRequest, "get proxy re-encryption capsule error", err.Error()))
		return
	}
	c.JSON(http.StatusOK,
		tsproto.NewResponse(http.StatusOK, "success", map[string]any{
			"capsule": capsule,
			"pubkey":  pubkey[:],
		}),
	)
}

func (h *ServerHandle) AddNodeAddressHeader(c *gin.Context) {
	c.Header("NodeAddress", h.nodeAddr)
}

type ReencryptReq struct {
	Did     string `json:"did"`
	Capsule []byte `json:"capsule"`
	Rk      []byte `json:"rk"`
}

func (h *ServerHandle) ReEncryptKey(c *gin.Context) {
	var req ReencryptReq
	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "re-encrypt key error", "bad request params"))
		return
	}
	newCapsule, err := h.gateway.ReEncryptKey(req.Did, req.Capsule, req.Rk)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "re-encrypt key error", err.Error()))
		return
	}
	c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", newCapsule))
}
