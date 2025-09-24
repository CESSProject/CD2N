package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/CESSProject/CD2N/cacher/client"
	"github.com/CESSProject/CD2N/cacher/config"
	"github.com/CESSProject/CD2N/cacher/utils"
	"github.com/CESSProject/go-sdk/chain"
	"github.com/CESSProject/go-sdk/libs/cache"
	"github.com/CESSProject/go-sdk/libs/tsproto"
	sdkutils "github.com/CESSProject/go-sdk/libs/utils"
	"github.com/CESSProject/go-sdk/logger"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	WORK_CLAIM_DATA = "claim_data"
	WORK_FETCH_DATA = "fetch_data"
	WORK_PUSH_DATA  = "push_data"
)

const (
	DATA_FLAG_EMPTY  = "empty"
	DATA_FLAG_ORIGIN = "origin"
	DATA_FLAG_NORMAL = "normal"
	DATA_FLAG_RAW    = "raw"
)

type FileInfo struct {
	Fid      string `json:"fid"`
	Storager string `json:"storager"`
}

type DataRetrieveTask struct {
	WorkType  string
	TeePubkey []byte
	Fid       string
	Path      string
	Storager  tsproto.StorageNode
	Task
}

type DataProvideTask struct {
	WorkType  string
	Fid       string
	Count     int
	Fragments []string
	Token     string
	Sign      string
	Path      string
	Storager  tsproto.StorageNode
	Task
}

type CessAccessTaskExecutor struct {
	taskCh       chan any
	pool         *ants.Pool
	nodeAcc      string
	tempDir      string
	privateKey   *ecdsa.PrivateKey
	selflessMode bool
	dataCache    *cache.Cache
	files        *leveldb.DB
	*StoragersManager
	RetrieverProvider
	SignTool
	AesKeyProvider
}

func NewCessAccessTaskExecutor(sk string, c *cache.Cache, retrievers RetrieverProvider, csize int, fdbPath, tempDir string, selfless bool) (*CessAccessTaskExecutor, error) {
	if csize <= 1 || csize > 1024 {
		csize = 1024
	}
	pool, err := ants.NewPool(csize / 2)
	if err != nil {
		return nil, errors.Wrap(err, "new cess access task executor error")
	}

	priKey, err := crypto.HexToECDSA(sk)
	if err != nil {
		return nil, errors.Wrap(err, "new cess access task executor error")
	}

	signTool, err := NewCessSignTool()
	if err != nil {
		return nil, errors.Wrap(err, "new cess access task executor error")
	}

	files, err := client.NewDB(fdbPath)
	if err != nil {
		return nil, errors.Wrap(err, "new cess access task executor error")
	}

	return &CessAccessTaskExecutor{
		taskCh:            make(chan any, csize),
		pool:              pool,
		nodeAcc:           crypto.PubkeyToAddress(priKey.PublicKey).Hex(),
		privateKey:        priKey,
		RetrieverProvider: retrievers,
		dataCache:         c,
		tempDir:           tempDir,
		StoragersManager:  NewStoragersManager(),
		files:             files,
		SignTool:          signTool,
		selflessMode:      selfless,
		AesKeyProvider:    new(EcdhAesKeyManager),
	}, nil
}

func (te *CessAccessTaskExecutor) GetFileInfo(did, fid string, net uint16) (FileInfo, error) {
	var finfo FileInfo
	err := client.GetData(te.files, did, &finfo)
	if err != nil {
		return finfo, errors.Wrap(err, "get file info error")
	}
	if finfo.Storager != "" {
		return finfo, nil
	}
	if fid == "" {
		return finfo, errors.Wrap(errors.New("file info not found"), "get file info error")
	}
	chainCli, err := chain.NewLightCessClient("", config.GetConfig().Rpcs)
	if err != nil {
		return finfo, errors.Wrap(err, "get file info error")
	}
	fmeta, err := chainCli.QueryFileMetadata(fid, 0)
	if err != nil {
		return finfo, errors.Wrap(err, "get file info error")
	}
	for _, seg := range fmeta.SegmentList {
		for _, frag := range seg.FragmentList {
			if string(frag.Hash[:]) != did {
				continue
			}
			minerAcc := utils.EncodePubkey(frag.Miner[:], net)
			if _, ok := te.GetStorager(minerAcc); ok {
				finfo.Fid = fid
				finfo.Storager = minerAcc
				return finfo, nil
			}
		}
	}
	return finfo, errors.Wrap(errors.New("file info not found"), "get file info error")
}

func (te *CessAccessTaskExecutor) Execute(task Task) error {
	switch task.Channel {
	case client.CHANNEL_PROVIDE:
		dpt := &DataProvideTask{
			Task:     task,
			Fid:      task.Did,
			Path:     path.Join(te.tempDir, task.Did),
			WorkType: WORK_CLAIM_DATA,
		}
		te.taskCh <- dpt
	case client.CHANNEL_RETRIEVE:
		retriever, ok := te.GetRetriever(task.Acc)
		if !ok {
			return errors.Wrap(errors.New("retriever not be found."), "execute cess access task error")
		}
		// retrieve data from loacl cache
		if item := te.dataCache.Get(task.Did); item.Key == "" || item.Value == "" {
			drp := &DataRetrieveTask{
				Task:      task,
				TeePubkey: retriever.TeePubkey,
				Path:      item.Value,
				WorkType:  WORK_FETCH_DATA,
			}
			te.taskCh <- drp
			return nil
		}
		// retrieve data from storager
		finfo, err := te.GetFileInfo(task.Did, task.ExtData, config.GetConfig().Network)
		if err != nil {
			return errors.Wrap(err, "execute cess access task error")
		}
		node, ok := te.GetStorager(finfo.Storager)
		if !ok {
			return errors.Wrap(errors.New("storage node not be found."), "execute cess access task error")
		}
		drp := &DataRetrieveTask{
			Task:      task,
			Fid:       finfo.Fid,
			TeePubkey: retriever.TeePubkey,
			Path:      path.Join(te.tempDir, task.Did),
			WorkType:  WORK_FETCH_DATA,
			Storager: tsproto.StorageNode{
				Endpoint: node.Endpoint,
				Account:  node.Account,
			},
		}
		te.taskCh <- drp
	default:
		return errors.Wrap(errors.New("invalid task"), "execute cess access task error")
	}
	return nil
}

func (te *CessAccessTaskExecutor) TaskExecutionServer(ctx context.Context) error {
	for {
		select {
		case t := <-te.taskCh:
			switch task := t.(type) {
			case *DataProvideTask:
				te.pool.Submit(func() {
					te.DataProvideHandle(task) //t.(*DataProvideTask)
				})
			case *DataRetrieveTask:
				te.pool.Submit(func() {
					te.DataRetrieveHandle(task) //t.(*DataRetrieveTask)
				})
			default:
				logger.GetLogger(config.LOG_TASK).Error("unresolved task type: ", t)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (te *CessAccessTaskExecutor) DataProvideHandle(task *DataProvideTask) {
	switch task.WorkType {
	case WORK_CLAIM_DATA:
		if err := te.ClaimDataFromRetriever(task); err != nil {
			logger.GetLogger(config.LOG_TASK).Error("failed to process data provision task: ", err)
			return
		}
		if task.Count <= 0 || len(task.Fragments) != task.Count {
			logger.GetLogger(config.LOG_TASK).Errorf("bad task: %s, fragment count: %d, target count: %d", task.Tid, len(task.Fragments), task.Count)
			return
		}
		task.Sign = ""
		task.Did = task.Fragments[0]
		task.Fragments = task.Fragments[1:]
		task.Path = path.Join(te.tempDir, task.Fid, task.Did)
		task.WorkType = WORK_FETCH_DATA
		if err := utils.MakeDir(path.Join(te.tempDir, task.Fid)); err != nil {
			logger.GetLogger(config.LOG_TASK).Error("failed to process data provision task: ", err)
			return
		}
		te.taskCh <- task
	case WORK_FETCH_DATA:
		if err := te.FetchDataFromRetriever(task); err != nil {
			logger.GetLogger(config.LOG_TASK).Error("failed to process data provision task: ", err)
			return
		}
		if task.Storager.Endpoint == "" || task.Storager.Account == "" {
			storager, err := te.GetMinerEndpoint(uint64(task.Count))
			if err != nil {
				logger.GetLogger(config.LOG_TASK).Error("failed to process data provision task: ", err)
				return
			}
			task.Storager = storager
		}
		task.WorkType = WORK_PUSH_DATA
		te.taskCh <- task
	case WORK_PUSH_DATA:
		if err := te.PushDataToStorageNode(task); err != nil {
			logger.GetLogger(config.LOG_TASK).Error("failed to process data provision task: ", err)
			return
		}
		if err := client.PutData(te.files, task.Did, FileInfo{
			Storager: task.Storager.Account,
			Fid:      task.Fid,
		}); err != nil {
			logger.GetLogger(config.LOG_TASK).Error("failed to process data provision task: ", err)
			return
		}
		if len(task.Fragments) <= 0 {
			logger.GetLogger(config.LOG_TASK).Infof(
				"provision task %s done, distributed to %s, fid: %s", task.Tid, task.Storager.Account, task.Fid,
			)
			return
		}
		if item := te.dataCache.Get(task.Did); item.Key == "" || item.Value == "" {
			if fs, err := os.Stat(task.Path); err == nil && !fs.IsDir() && fs.Size() > 0 {
				te.dataCache.AddWithData(task.Did, task.Path, fs.Size())
			}
		}
		logger.GetLogger(config.LOG_TASK).Infof(
			"distributed file %s fragment[%d] %s to miner %s done.",
			task.Fid, task.Count-len(task.Fragments), task.Did, task.Storager.Account,
		)
		task.Did = task.Fragments[0]
		task.Path = path.Join(te.tempDir, task.Fid, task.Did)
		task.Fragments = task.Fragments[1:]
		task.WorkType = WORK_FETCH_DATA
		te.taskCh <- task
	}
}

func (te *CessAccessTaskExecutor) DataRetrieveHandle(task *DataRetrieveTask) {
	switch task.WorkType {
	case WORK_FETCH_DATA:
		if err := te.RetrieveData(task); err != nil {
			logger.GetLogger(config.LOG_TASK).Error("failed to process data retrieval task", err)
			return
		}
		task.WorkType = WORK_PUSH_DATA
		te.taskCh <- task
	case WORK_PUSH_DATA:
		if err := te.PushRetrievalData(task); err != nil {
			logger.GetLogger(config.LOG_TASK).Error("failed to process data retrieval task", err)
			return
		}
		if item := te.dataCache.Get(task.Did); item.Value != "" {
			return
		}
		if fs, err := os.Stat(task.Path); err == nil && !fs.IsDir() && fs.Size() > 0 {
			te.dataCache.AddWithData(task.Did, task.Path, fs.Size())
		}
	}
}

func (te *CessAccessTaskExecutor) RetrieveData(task *DataRetrieveTask) error {
	if item := te.dataCache.Get(task.Did); item.Value != "" {
		if fs, err := os.Stat(item.Value); err == nil && !fs.IsDir() && fs.Size() > 0 {
			task.Path = item.Value
			logger.GetLogger(config.LOG_TASK).Infof("retrieve data %s form cache", task.Did)
			return nil
		}
	}
	u, err := url.JoinPath(task.Storager.Endpoint, "fragment")
	if err != nil {
		return errors.Wrap(err, "retrieve data error")
	}
	acc, msg, sign := te.GetSignInfoTuple()
	if err = tsproto.GetFileFromStorageNode(u, acc, msg, sign, task.Fid, task.Did, task.Path); err != nil {
		return errors.Wrap(err, "retrieve data error")
	}
	logger.GetLogger(config.LOG_TASK).Infof("retriever data %s form miner %s", task.Did, task.Storager.Account)
	return nil
}

func (te *CessAccessTaskExecutor) PushRetrievalData(task *DataRetrieveTask) error {
	var (
		aeskey, pubkey []byte
		epath          string = task.Path
	)

	fs, err := os.Stat(task.Path)
	if err != nil {
		return errors.Wrap(err, "push retrieval data error")
	}

	if !te.selflessMode {
		aeskey, pubkey, err = te.GetAESKey(task.TeePubkey)
		if err != nil {
			return errors.Wrap(err, "push retrieval data error")
		}
		//encrypt file
		tidBytes, _ := hex.DecodeString(task.Tid)
		epath, err = utils.EncryptFile(task.Path, aeskey, tidBytes)
		if err != nil {
			return errors.Wrap(err, "push retrieval data error")
		}
		defer os.Remove(epath)
	}

	fmeta := tsproto.FileMeta{
		Tid:       task.Tid,
		Did:       task.Did,
		Size:      fs.Size(),
		Key:       hex.EncodeToString(pubkey),
		Provider:  te.nodeAcc,
		Timestamp: time.Now().Format(TIME_LAYOUT),
	}
	jbytes, err := json.Marshal(fmeta)
	if err != nil {
		return errors.Wrap(err, "push retrieval data error")
	}
	u, err := url.JoinPath(task.Addr, tsproto.PUSH_DATA_URL)
	if err != nil {
		return errors.Wrap(err, "push retrieval data error")
	}

	if _, err = tsproto.PushFile(u, epath,
		map[string][]byte{"metadata": jbytes}); err != nil {
		return errors.Wrap(err, "push retrieval data error")
	}
	logger.GetLogger(config.LOG_TASK).Infof("provide retrieved data %s ", task.Did)
	return nil
}

func (te *CessAccessTaskExecutor) ClaimDataFromRetriever(task *DataProvideTask) error {
	req := tsproto.FileRequest{
		Pubkey:       crypto.CompressPubkey(&te.privateKey.PublicKey),
		Fid:          task.Fid,
		StorageNodes: te.ExportStorages(),
		Timestamp:    time.Now().Format(TIME_LAYOUT),
	}
	jbytes, _ := json.Marshal(&req)
	sign, _ := utils.SignWithSecp256k1PrivateKey(te.privateKey, jbytes)
	req.Sign = hex.EncodeToString(sign)
	u, err := url.JoinPath(task.Addr, tsproto.CLAIM_DATA_URL)
	if err != nil {
		return errors.Wrap(err, "claim data from retriever error")
	}
	resp, err := tsproto.ClaimFile(u, req)
	if err != nil {
		te.ErrorFeedback(task.Acc)
		return errors.Wrap(err, "claim data from retriever error")
	}
	task.Token = resp.Token
	task.Fragments = resp.Fragments
	task.Count = len(resp.Fragments)
	return nil
}

func (te *CessAccessTaskExecutor) FetchDataFromRetriever(task *DataProvideTask) error {
	// get data from cache
	if item := te.dataCache.Get(task.Did); item.Value != "" {
		if fs, err := os.Stat(item.Value); err == nil && !fs.IsDir() && fs.Size() > 0 {
			task.Path = item.Value
			logger.GetLogger(config.LOG_TASK).Infof("get provide data %s form cache", task.Did)
			return nil
		}
	} else if task.Token == "" {
		return errors.Wrap(errors.New("empty data-fetch token"), "fetch data from retriever error")
	}
	u, err := url.JoinPath(task.Addr, tsproto.FETCH_DATA_URL)
	if err != nil {
		return errors.Wrap(err, "fetch data from retriever error")
	}
	// data, err := tsproto.FetchFile(u, task.Token, task.Fid, task.Did)
	// if err != nil {
	// 	te.ErrorFeedback(task.Acc)
	// 	return errors.Wrap(err, "fetch data from retriever error")
	// }
	// f, err := os.Create(task.Path)
	// if err != nil {
	// 	return errors.Wrap(err, "fetch data from retriever error")
	// }
	// defer f.Close()

	// if _, err = f.Write(data); err != nil {
	// 	return errors.Wrap(err, "fetch data from retriever error")
	// }
	flag, data, err := tsproto.FetchDataAndFlag(u, task.Token, task.Fid, task.Did)
	if err != nil {
		te.ErrorFeedback(task.Acc)
		return errors.Wrap(err, "fetch data from retriever error")
	}
	if err = DataProcessing(data, task.Did, task.Path, flag); err != nil {
		return errors.Wrap(err, "fetch data from retriever error")
	}
	logger.GetLogger(config.LOG_TASK).Infof(
		"task[%s(token:%s)]: fetch file %s fragment %s for miner %s success",
		task.Tid, task.Token, task.Fid, task.Did, task.Storager.Account,
	)
	return nil
}

func DataProcessing(source []byte, did, fpath, flag string) error {
	var (
		target []byte
	)
	switch flag {
	case DATA_FLAG_EMPTY:
		target = make([]byte, FRAGMENT_SIZE)
	case DATA_FLAG_ORIGIN, DATA_FLAG_NORMAL:
		target := make([]byte, FRAGMENT_SIZE)
		copy(target, source)
	case DATA_FLAG_RAW:
		segment := make([]byte, SEGMENT_SIZE)
		copy(segment, source)
		hash := sha256.New()
		got := false
		if err := sdkutils.ReedSolomonWithHandle(segment, func(shard []byte) error {
			if got {
				return nil
			}
			hash.Reset()
			hash.Write(shard)
			fragment := hex.EncodeToString(hash.Sum(nil))
			if fragment == did {
				target = shard
				got = true
			}
			return nil
		}); err != nil {
			return errors.Wrap(err, "processing data error")
		}
	}
	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "processing data error")
	}
	defer f.Close()

	if _, err = f.Write(target); err != nil {
		return errors.Wrap(err, "processing data error")
	}
	return nil
}

func (te *CessAccessTaskExecutor) PushDataToStorageNode(task *DataProvideTask) error {
	u, err := url.JoinPath(task.Storager.Endpoint, "fragment")
	if err != nil {
		return errors.Wrap(err, "push data to storage node error")
	}
	acc, msg, sign := te.GetSignInfoTuple()
	if err := tsproto.PushFileToStorageNode(u, acc, msg, sign, task.Fid, task.Did, task.Path); err != nil {
		return errors.Wrap(err, "push data to storage node error")
	}
	logger.GetLogger(config.LOG_TASK).Infof("push data %s fragment %s to miner %s success.", task.Fid, task.Did, task.Storager.Account)
	return nil
}
