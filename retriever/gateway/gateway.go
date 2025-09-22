package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/alert"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CESSProject/cess-crypto/gosdk"
	"github.com/CESSProject/go-sdk/chain"
	"github.com/CESSProject/go-sdk/chain/evm"
	"github.com/CESSProject/go-sdk/libs/buffer"
	"github.com/CESSProject/go-sdk/libs/tsproto"
	"github.com/CESSProject/go-sdk/libs/utils"
	"github.com/CESSProject/go-sdk/logger"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/go-redis/redis/v8"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

const (
	EMPTY_FRAGMENT_HASH = "2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74"
	DATA_FLAG_EMPTY     = "empty"
	DATA_FLAG_ORIGIN    = "origin"
	DATA_FLAG_NORMAL    = "normal"
	DATA_FLAG_RAW       = "raw"
)

type Status struct {
	Ongoing  uint64
	Done     uint64
	Retried  uint64
	FidNum   uint64
	DlingNum uint64
}

type DataRecord struct {
	Fragments []string `json:"fragments"`
}

type Cd2nNode struct {
	tsproto.Cd2nNode
	SendBytes    uint64 `json:"send_bytes"`
	ReceiveBytes uint64 `json:"receive_bytes"`
	SuccessCount uint64 `json:"success_count"`
	FailedCount  uint64 `json:"failed_count"`
	Available    bool   `json:"available"`
}

type _PreProcessJob struct {
	filePath  string
	acc       []byte
	territory string
	fileName  string
	encrypt   bool
	res       chan task.FileInfo
	err       chan error
}

type Gateway struct {
	nodeAcc         string
	preprocessChan  chan _PreProcessJob
	alarm           alert.AlertHandler
	redisCli        *redis.Client
	cessCli         *chain.Client
	pool            *ants.Pool
	pstats          *task.ProvideStat
	contract        *evm.CacheProtoContract
	FileCacher      *buffer.FileBuffer
	cm              *CryptoModule
	txPool          *ants.Pool
	dlPool          *ants.Pool
	offloadingQueue chan DataUnit
	keyLock         *task.EasyKeyLock
}

func NewGateway(redisCli *redis.Client, contract *evm.CacheProtoContract, cacher *buffer.FileBuffer) (*Gateway, error) {
	conf := config.GetConfig()
	pool, err := ants.NewPool(conf.UploadThreadNum)
	if err != nil {
		return nil, errors.Wrap(err, "new gateway error")
	}
	dlPool, err := ants.NewPool(conf.DownloadThreadNum)
	if err != nil {
		return nil, errors.Wrap(err, "new gateway error")
	}
	txPool, err := ants.NewPool(500)
	if err != nil {
		return nil, errors.Wrap(err, "new gateway error")
	}
	cm, err := NewCryptoModule(redisCli)
	if err != nil {
		return nil, errors.Wrap(err, "new gateway error")
	}
	gateway := &Gateway{
		nodeAcc:  contract.Node.Hex(),
		redisCli: redisCli,
		contract: contract,
		alarm:    alert.DefaultAlarm{},
		pstats: &task.ProvideStat{
			Ongoing: &atomic.Int64{},
			Done:    &atomic.Int64{},
			Retried: &atomic.Int64{},
			Fids:    &sync.Map{},
		},
		preprocessChan:  make(chan _PreProcessJob, conf.UploadChannelSize),
		pool:            pool,
		dlPool:          dlPool,
		txPool:          txPool,
		FileCacher:      cacher,
		cm:              cm,
		offloadingQueue: make(chan DataUnit, 98304),
		keyLock:         &task.EasyKeyLock{Map: &sync.Map{}},
	}
	_, err = gateway.GetCessClient()
	if err != nil {
		return nil, errors.Wrap(err, "new gateway error")
	}
	return gateway, nil
}

func (g *Gateway) Register(handler alert.AlertHandler) {
	//handler.Alert("info", "The Lark alarm module has been registered with the gateway.")
	g.alarm = handler
}

func (g *Gateway) GatewayStatus() Status {
	var num uint64
	g.pstats.Fids.Range(
		func(key, value any) bool {
			num++
			return true
		})
	ongoing := max(g.pstats.Ongoing.Load(), 0)
	return Status{
		Ongoing: uint64(ongoing),
		Done:    uint64(g.pstats.Done.Load()),
		Retried: uint64(g.pstats.Retried.Load()),
		FidNum:  num,
	}
}

func (g *Gateway) CheckAndCreateOrder(ctx context.Context, node Cd2nNode, traffic string) error {
	if config.GetConfig().Debug {
		return nil
	}
	u, err := url.JoinPath(node.EndPoint, tsproto.QUERY_CAPACITY_URL)
	if err != nil {
		return errors.Wrap(err, "check and create order error")
	}
	cap, err := tsproto.QueryRemainCap(u, g.contract.Node.Hex())
	if err != nil {
		return errors.Wrap(err, "check and create order error")
	}
	if cap >= 8*config.MIB {
		return nil
	}
	addr := common.HexToAddress(node.TeeAddr)
	_, err = g.contract.CreateCacheOrder(ctx, addr, traffic)
	if err != nil {
		return errors.Wrap(err, "check and create order error")
	}
	return nil
}

func (g *Gateway) WaitFileCache(key string, timeout time.Duration) error {
	timer := time.NewTimer(timeout)

	for {
		select {
		case <-timer.C:
			return errors.New("timeout")
		default:
			if ok, _ := client.SetNxMessage(
				g.redisCli, context.Background(),
				fmt.Sprintf("dlkey-%s", key), []byte{}, timeout,
			); !ok {
				return nil
			}
			time.Sleep(time.Millisecond * 300)
		}
	}
}

func (g *Gateway) ReleaseCacheTask(key string) {
	client.DeleteMessage(g.redisCli, context.Background(), fmt.Sprintf("dlkey-%s", key))
}

func (g *Gateway) PutProvideTask(key string, ftask task.ProvideTask) error {
	if err := client.PutDataToRedis(
		g.redisCli, context.Background(),
		fmt.Sprintf("%s-ftask_key-%s", g.nodeAcc, key), ftask, time.Hour*24,
	); err != nil {
		return errors.Wrap(err, "put provide task error")
	}
	return nil
}

func (g *Gateway) GetProvideTask(key string, value any) error {
	if err := client.GetDataFromRedis(
		g.redisCli, context.Background(),
		fmt.Sprintf("%s-ftask_key-%s", g.nodeAcc, key), value,
	); err != nil {
		return errors.Wrap(err, "get provide task error")
	}
	return nil
}

func (g *Gateway) CompositeSegment(segmentId string, fragPaths []string) (string, error) {
	var (
		segPath string
		err     error
	)
	segPath, err = g.FileCacher.NewBufPath(segmentId)
	if err != nil {
		return "", errors.Wrap(err, "composite segment with fragments error")
	}
	err = utils.RSRestore(segPath, fragPaths)
	if err != nil {
		return "", errors.Wrap(err, "composite segment with fragments error")
	}
	g.FileCacher.AddData(segmentId, segPath)
	return segPath, nil
}

func (g *Gateway) CombineFileIntoCache(fid string, fsize int64, segPaths []string) (string, error) {
	var (
		fpath string
		err   error
	)
	if fsize <= 0 {
		fsize = config.SEGMENT_SIZE
	}
	fpath, err = g.FileCacher.NewBufPath(fid)
	if err != nil {
		return "", errors.Wrap(err, "combine file into gateway cache error")
	}
	f, err := os.Create(fpath)
	if err != nil {
		return "", errors.Wrap(err, "combine file into gateway cache error")
	}
	defer f.Close()
	var size int64
	for _, segPath := range segPaths {
		buf, err := os.ReadFile(segPath)
		if err != nil {
			return "", errors.Wrap(err, "combine file into gateway cache error")
		}
		size += int64(len(buf))
		if size > fsize { //remove random padding data
			buf = buf[:config.SEGMENT_SIZE-(size-fsize)]
		}
		_, err = f.Write(buf)
		if err != nil {
			return "", errors.Wrap(err, "combine file into gateway cache error")
		}
	}
	g.FileCacher.AddData(fid, fpath)
	return fpath, nil
}

func (g *Gateway) ProcessFile(buf *buffer.FileBuffer, name, fpath, territory string, owner []byte) (task.FileInfo, error) {
	baseDir, err := buf.NewBufDir(hex.EncodeToString(utils.CalcSha256Hash([]byte(fpath))))
	if err != nil {
		return task.FileInfo{}, errors.Wrap(err, "process file error")
	}
	fstat, err := os.Stat(fpath)
	if err != nil {
		return task.FileInfo{}, errors.Wrap(err, "process file error")
	}
	finfo := task.FileInfo{
		FileName:  name,
		BaseDir:   baseDir,
		FileSize:  fstat.Size(),
		Owner:     owner,
		Territory: territory,
	}
	f, err := os.Open(fpath)
	if err != nil {
		return task.FileInfo{}, errors.Wrap(err, "process file error")
	}
	defer f.Close()
	count := fstat.Size() / config.SEGMENT_SIZE
	if fstat.Size()%config.SEGMENT_SIZE != 0 {
		count++
	}

	hash := sha256.New()
	fbuf := make([]byte, config.SEGMENT_SIZE)
	for i := int64(0); i < count; i++ {
		hash.Reset()
		smallDataFlag := false
		if n, err := f.Read(fbuf); err != nil {
			return task.FileInfo{}, errors.Wrap(err, "process file error")
		} else if n < config.SEGMENT_SIZE {
			smallDataFlag = n <= config.FRAGMENT_SIZE
			if err = utils.FillZeroData(fbuf[n:]); err != nil {
				return task.FileInfo{}, errors.Wrap(err, "process file error")
			}
		}
		var fragments []string
		hash.Write(fbuf)
		segment := hex.EncodeToString(hash.Sum(nil))
		index := 0
		finfo.Segments = append(finfo.Segments, segment)
		if err = utils.ReedSolomonWithHandle(fbuf, func(shard []byte) error {
			index++
			hash.Reset()
			hash.Write(shard)
			fragment := hex.EncodeToString(hash.Sum(nil))
			fragments = append(fragments, fragment)
			if index <= config.FRAGMENTS_NUM || fragment == EMPTY_FRAGMENT_HASH || smallDataFlag {
				// Optimization: do not save fragment data of empty, original, or small file
				return nil
			}
			fragPath, err := buf.JoinPath(baseDir, fragment)
			if err != nil {
				return err
			}
			if err = utils.WriteFile(fragPath, shard); err != nil {
				return err
			}
			buf.AddData(fragment, fragPath)
			return nil
		}); err != nil {
			return task.FileInfo{}, errors.Wrap(err, "process file error")
		}
		finfo.Fragments = append(finfo.Fragments, fragments)
	}
	hash.Reset()
	for _, segment := range finfo.Segments {
		bytes, _ := hex.DecodeString(segment)
		hash.Write(bytes)
	}
	finfo.Fid = hex.EncodeToString(hash.Sum(nil))
	return finfo, nil
}

func (g *Gateway) CreateStorageOrder(info task.FileInfo) (string, error) {
	var (
		segments []chain.SegmentList
		user     chain.UserBrief
		hash     string
	)
	for i, v := range info.Fragments {
		segment := chain.SegmentList{
			SegmentHash:  getFileHash(info.Segments[i]),
			FragmentHash: make([]chain.FileHash, len(v)),
		}
		for j, fragment := range v {
			segment.FragmentHash[j] = getFileHash(fragment)
		}
		segments = append(segments, segment)
	}
	acc, err := types.NewAccountID(info.Owner)
	if err != nil {
		return "", errors.Wrap(err, "create storage order error")
	}
	user.User = *acc
	user.FileName = types.NewBytes([]byte(info.FileName))
	user.TerriortyName = types.NewBytes([]byte(info.Territory))
	g.txPool.Submit(func() {
		hash, err = g.cessCli.UploadDeclaration(getFileHash(info.Fid), segments, user, uint64(info.FileSize), nil, nil)
		if err != nil && strings.Contains(err.Error(), "Insufficient balance") {
			g.alarm.Alert("warn", err.Error())
		}
	})
	return hash, errors.Wrap(err, "create storage order error")
}

func (g *Gateway) CreateFlashStorageOrder(owner []byte, fid, filename, territory string) (string, error) {
	var hash string
	cli, err := g.GetCessClient()
	if err != nil {
		return "", errors.Wrap(err, "create flash storage order error")
	}
	meta, err := cli.QueryFileMetadata(fid, 0)
	if err != nil {
		return "", errors.Wrap(err, "create flash storage order error")
	}
	acc, err := types.NewAccountID(owner)
	if err != nil {
		return "", errors.Wrap(err, "create flash storage order error")
	}
	user := chain.UserBrief{
		User:          *acc,
		FileName:      types.NewBytes([]byte(filename)),
		TerriortyName: types.NewBytes([]byte(territory)),
	}
	var segments []chain.SegmentList
	for _, v := range meta.SegmentList {
		segment := chain.SegmentList{
			SegmentHash:  v.Hash,
			FragmentHash: make([]chain.FileHash, len(v.FragmentList)),
		}
		for i, v := range v.FragmentList {
			segment.FragmentHash[i] = v.Hash
		}
		segments = append(segments, segment)
	}
	g.txPool.Submit(func() {
		hash, err = cli.UploadDeclaration(getFileHash(fid), segments, user, meta.FileSize.Uint64(), nil, nil)
		if err != nil && strings.Contains(err.Error(), "Insufficient balance") {
			g.alarm.Alert("warn", err.Error())
		}
	})
	return hash, errors.Wrap(err, "create flash storage order error")
}

func (g *Gateway) PreprocessFile(ctx context.Context, b *buffer.FileBuffer, file io.Reader, acc []byte, territory, filename string, encrypt bool) (task.FileInfo, error) {
	var (
		finfo task.FileInfo
		err   error
	)

	if len(filename) > 63 {
		filename = filename[len(filename)-63:]
	}
	tmpName := hex.EncodeToString(utils.CalcSha256Hash(acc, []byte(territory+filename)))
	fpath, err := b.NewBufPath(tmpName)
	if err != nil {
		return finfo, errors.Wrap(err, "pre process file error")
	}

	if err = SaveDataToBuf(file, fpath); err != nil {
		return finfo, errors.Wrap(err, "pre process file error")
	}

	job := _PreProcessJob{
		acc:       acc,
		fileName:  filename,
		territory: territory,
		filePath:  fpath,
		encrypt:   encrypt,
		res:       make(chan task.FileInfo, 1),
		err:       make(chan error, 1),
	}
	select {
	case g.preprocessChan <- job:
	case <-ctx.Done():
		return finfo, errors.Wrap(errors.New("preprocessing timeout"), "pre process file error")
	}
	select {
	case finfo = <-job.res:
		return finfo, nil
	case err = <-job.err:
		return finfo, errors.Wrap(err, "pre process file error")
	case <-ctx.Done():
		return finfo, errors.Wrap(errors.New("preprocessing timeout"), "pre process file error")
	}
}

func (g *Gateway) PreprocessDataServer(ctx context.Context, b *buffer.FileBuffer) {
	for jb := range g.preprocessChan {
		pjob := jb
		if err := g.pool.Submit(func() {
			var capsule *gosdk.Capsule
			if pjob.encrypt {
				rpath, err := b.NewBufPath(
					hex.EncodeToString(
						utils.CalcSha256Hash(pjob.acc, []byte(pjob.territory+pjob.fileName), []byte("encrypt")),
					),
				)
				if err != nil {
					pjob.err <- err
					return
				}
				if capsule, err = g.cm.EncryptFile(pjob.filePath, rpath, pjob.acc); err != nil {
					pjob.err <- err
					return
				}
				if err := os.RemoveAll(pjob.filePath); err != nil {
					pjob.err <- err
					return
				}
				pjob.filePath = rpath
			}

			finfo, err := g.ProcessFile(b, pjob.fileName, pjob.filePath, pjob.territory, pjob.acc)
			if err != nil {
				pjob.err <- err
				return
			}
			cachePath, err := g.FileCacher.NewBufPath(finfo.Fid)
			if err != nil {
				pjob.err <- err
				return
			}

			err = os.Rename(pjob.filePath, cachePath)
			if err != nil {
				pjob.err <- err
				return
			}

			g.FileCacher.AddData(finfo.Fid, buffer.CatNamePath(pjob.fileName, cachePath))

			if pjob.encrypt && capsule != nil {
				if err = g.cm.SaveCapsule(finfo.Fid, capsule); err != nil {
					pjob.err <- err
					return
				}
			}
			pjob.res <- finfo
		}); err != nil {
			logger.GetLogger(config.LOG_GATEWAY).Error("an error occurred while performing data preprocessing ", err)
		}
	}
}

func getFileHash(fid string) chain.FileHash {
	var hash chain.FileHash
	for i := 0; i < len(fid) && i < len(hash); i++ {
		hash[i] = types.U8(fid[i])
	}
	return hash
}

func SaveDataToBuf(src io.Reader, fpath string) error {

	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return errors.Wrap(err, "cache file error")
}
