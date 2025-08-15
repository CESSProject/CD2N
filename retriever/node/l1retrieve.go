package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/bits-and-blooms/bloom/v3"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

const (
	//Back Fetch Broadcast
	ABORT_BACK_FETCH   = 4
	ABORT_JUMP_REQUEST = 2
	ABORT_BORADCAST    = 1
)

func Abort(point, flag int) bool {
	switch flag {
	case ABORT_BACK_FETCH, ABORT_JUMP_REQUEST, ABORT_BORADCAST:
	default:
		return false
	}
	if point < 0 || point > 7 {
		return false
	}
	return (point & flag) != 0
}

type RetrieverTask interface {
	InjectResources(executor Executor, nodes NodesProvider, tools ToolsProvider, filters ...RequestFilter)
	Execute(ctx context.Context) ([]string, error)
	String() string
}

type Executor interface {
	BatchExecutor(ctx context.Context, indicators int, worker Worker, uris ...string) []string
	Executor(ctx context.Context, worker Worker, uri string) (string, error)
}

type NodesProvider interface {
	LoadAllRetrievers(limit int) []Retriever
	LocatingResources(storageNodes []string) (Retriever, bool)
	CacherRetrieval(addr string, success bool)
	RetrieverReceive(addr string, bytes uint64)
}

type RequestFilter interface {
	Abort(user string, dids ...string) int
}

type ToolsProvider interface {
	L2Retriever
	GetDataFromRemote(did, extData string, node Retriever) (string, error)
	NewBufPath(paths ...string) (string, error)
	AddData(key string, fpath string)
	SignRequestTool() (string, []byte, error)
	GetIpfsShell() (*shell.Shell, error)
}

type Worker func(context.Context, string) (string, error)

type EthSign func(data []byte) ([]byte, error)

type ResourceRetriever struct {
	nodeAddr   string
	fileFilter *bloom.BloomFilter
	pool       *ants.Pool
	ipfsShell  *shell.Shell
	*buffer.FileBuffer
	*NodeManager
	EthSign
	L2Retriever
}

func NewResourceRetriever(threadNum int, nodeAddr string, nodeMgr *NodeManager, buf *buffer.FileBuffer, l2ret L2Retriever, sign EthSign) (*ResourceRetriever, error) {
	if threadNum <= 0 || threadNum > 256 {
		threadNum = 256
	}
	pool, err := ants.NewPool(threadNum)
	if err != nil {
		return nil, errors.Wrap(err, "new resource retriever error")
	}
	return &ResourceRetriever{
		nodeAddr:    nodeAddr,
		fileFilter:  bloom.NewWithEstimates(100000000, 0.01),
		pool:        pool,
		NodeManager: nodeMgr,
		EthSign:     sign,
		L2Retriever: l2ret,
		FileBuffer:  buf,
	}, nil
}

func (rr *ResourceRetriever) GetIpfsShell() (*shell.Shell, error) {
	if rr.ipfsShell != nil && rr.ipfsShell.IsUp() {
		return rr.ipfsShell, nil
	}
	rr.ipfsShell = shell.NewShell(config.GetConfig().IpfsHost)

	if !rr.ipfsShell.IsUp() {
		return nil, errors.New("no valid connection established")
	}
	return rr.ipfsShell, nil
}

func (rr *ResourceRetriever) GetDataFromRemote(did, extData string, node Retriever) (string, error) {
	var fpath string
	u, err := url.JoinPath(node.Info.Endpoint, tsproto.FETCH_CACHE_DATA_URL)
	if err != nil {
		return fpath, errors.Wrap(err, "retrieve data from remote retriever error")
	}

	reqId, sign, err := rr.SignRequestTool()
	if err != nil {
		return fpath, errors.Wrap(err, "retrieve data from remote retriever error")
	}
	req := tsproto.CacheRequest{
		Did:       did,
		UserAddr:  utils.Remove0x(rr.nodeAddr),
		ExtData:   extData,
		Sign:      sign,
		Exp:       int64(time.Second * 12),
		RequestId: reqId,
	}
	jbytes, err := json.Marshal(req)
	if err != nil {
		return fpath, errors.Wrap(err, "retrieve data from remote retriever error")
	}
	headers := map[string]string{"Content-Type": "application/json"}
	bytes, err := tsproto.SendHttpRequest(http.MethodPost, u, headers, bytes.NewBuffer(jbytes))
	if err != nil {
		rr.RetrieverReceive(node.Info.Address, 0)
		return fpath, errors.Wrap(err, "retrieve data from remote retriever error")
	}
	fpath, err = rr.NewBufPath(did)
	if err != nil {
		return fpath, errors.Wrap(err, "retrieve data from remote retriever error")
	}
	f, err := os.Create(fpath)
	if err != nil {
		return fpath, errors.Wrap(err, "retrieve data from remote retriever error")
	}
	n, err := f.Write(bytes)
	if err != nil {
		f.Close()
		return fpath, errors.Wrap(err, "retrieve data from remote retriever error")
	}
	f.Close()
	rr.AddData(did, fpath)
	rr.RetrieverReceive(node.Info.Address, uint64(n))
	return fpath, nil
}

func (rr *ResourceRetriever) RecordUploadedFile(fid string) {
	fid = utils.Remove0x(fid)
	if bFid, err := hex.DecodeString(fid); err == nil {
		rr.fileFilter.TestOrAdd(bFid)
	}
}

func (rr *ResourceRetriever) TestUploadedFile(fid string) bool {
	fid = utils.Remove0x(fid)
	if bFid, err := hex.DecodeString(fid); err == nil {
		return rr.fileFilter.Test(bFid)
	}
	return false
}

func (rr *ResourceRetriever) Execute(ctx context.Context, task RetrieverTask) ([]string, error) {

	return task.Execute(ctx)
}

func (rr *ResourceRetriever) BatchExecutor(ctx context.Context, indicators int, worker Worker, uris ...string) []string {
	if indicators <= 0 {
		indicators = len(uris)
	}
	subWg := &sync.WaitGroup{}
	pathSet, pathCount := make(chan string, len(uris)), &atomic.Int32{}

	for i, u := range uris {
		subWg.Add(1)
		uri := u
		err := rr.pool.Submit(func() {
			defer subWg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				rpath, err := worker(ctx, uri)
				if err != nil {
					logger.GetLogger(config.LOG_RETRIEVE).Error("batch retrieval data error  ", err)
					return
				}
				if rpath != "" {
					pathSet <- rpath
					pathCount.Add(1)
				}
			}
		})
		if err != nil {
			logger.GetLogger(config.LOG_RETRIEVE).Error("batch retrieval data error  ", err)
		}
		if (i > 0 || indicators == 1) && (i+1)%indicators == 0 {
			subWg.Wait()
			if pathCount.Load() >= int32(indicators) {
				logger.GetLogger(config.LOG_RETRIEVE).Info("batch retrieve success")
				break
			}
			subWg = &sync.WaitGroup{}
		}
	}
	subWg.Wait()
	close(pathSet)
	var paths []string
	for p := range pathSet {
		paths = append(paths, p)
	}
	return paths
}
func (rr *ResourceRetriever) Executor(ctx context.Context, worker Worker, uri string) (string, error) {

	select {
	case <-ctx.Done():
		err := ctx.Err()
		if err != nil {
			err = errors.New("task failed")
		}
		return "", errors.Wrap(err, "execute task worker error")
	default:
	}
	rpath, err := worker(ctx, uri)
	if err != nil {
		return rpath, errors.Wrap(err, "execute task worker error")
	}
	return rpath, nil
}

func (rr *ResourceRetriever) SignRequestTool() (string, []byte, error) {
	reqIdBytes, err := utils.GetRandomBytes()
	if err != nil {
		return "", nil, err
	}
	reqId := hex.EncodeToString(reqIdBytes)
	sign, err := rr.EthSign([]byte(reqId))
	if err != nil {
		return "", nil, err
	}
	return reqId, sign, nil
}

func (rr *ResourceRetriever) RetrieveData(ctx context.Context, task RetrieverTask, filter ...RequestFilter) ([]string, error) {
	task.InjectResources(rr, rr, rr, filter...)
	return rr.Execute(ctx, task)
}

type IpfsRetrievalTask struct {
	Cid        string
	User       string
	FilePath   string
	FiltePoint int
	Filters    []RequestFilter
	Executor
	ToolsProvider
}

func NewIpfsRetrievalTask(cid, user, fpath string) *IpfsRetrievalTask {
	return &IpfsRetrievalTask{Cid: cid, User: user, FilePath: fpath}
}

func (t *IpfsRetrievalTask) InjectResources(executor Executor, nodes NodesProvider, tools ToolsProvider, filters ...RequestFilter) {
	t.Executor = executor
	t.ToolsProvider = tools
	t.Filters = filters
}

func (t *IpfsRetrievalTask) Execute(ctx context.Context) ([]string, error) {
	for _, f := range t.Filters {
		t.FiltePoint += f.Abort(t.User, t.Cid)
	}
	fpath, err := t.Executor.Executor(ctx, func(ctx context.Context, s string) (string, error) {
		if !Abort(t.FiltePoint, ABORT_BACK_FETCH) {
			return "", errors.Wrap(errors.New("abort retrieving data from IPFS node"), "execute worker error")
		}
		shell, err := t.GetIpfsShell()
		if err != nil {
			return "", errors.Wrap(err, "execute worker error")
		}
		reader, err := shell.Cat(t.Cid)
		if err != nil {
			return "", errors.Wrap(err, "execute worker error")
		}

		defer reader.Close()
		file, err := os.Open(t.FilePath)
		if err != nil {
			return "", errors.Wrap(err, "execute worker error")
		}
		defer file.Close()

		if _, err = io.Copy(file, reader); err != nil {
			return "", errors.Wrap(err, "execute worker error")
		}
		return t.FilePath, nil
	}, t.Cid)
	if err != nil {
		return nil, errors.Wrap(err, "execute IPFS Network data retrieval task error")
	}
	return []string{fpath}, nil
}

func (t IpfsRetrievalTask) String() string {
	return fmt.Sprintf("[IPFS Network Retrieve Task]->{Cid: %s}", t.Cid)
}

type CessRetrievalTask struct {
	Executor
	NodesProvider
	ToolsProvider
	cli        *chain.Client
	Filters    []RequestFilter
	FiltePoint int
	User       string
	Fid        string
	Segment    string
	Fragments  []string
}

func NewCesRetrieveTask(cli *chain.Client, user, fid, segment string, fragments []string) RetrieverTask {
	return &CessRetrievalTask{
		cli:       cli,
		User:      user,
		Fid:       fid,
		Segment:   segment,
		Fragments: fragments,
	}
}

func (t *CessRetrievalTask) InjectResources(executor Executor, nodes NodesProvider, tools ToolsProvider, filters ...RequestFilter) {
	t.Executor = executor
	t.NodesProvider = nodes
	t.ToolsProvider = tools
	t.Filters = filters
}

func (t CessRetrievalTask) Execute(ctx context.Context) ([]string, error) {
	//Query whether the data is reachable from this node
	for _, f := range t.Filters {
		t.FiltePoint += f.Abort(t.User, t.Fragments...)
	}
	nodes, err := t.QueryStorageNodes()
	if err != nil {
		return nil, errors.Wrap(err, "execute CESS Network data retrieval task error")
	}
	retriever, ok := t.LocatingResources(nodes)
	if ok {
		fpaths := t.BatchExecutor(ctx, len(t.Fragments)-config.PARITY_NUM,
			func(ctx context.Context, did string) (string, error) {
				//access L2 cache to retrieve data from this node
				if retriever.Info.Endpoint == "" && retriever.Info.Address == "" && !Abort(t.FiltePoint, ABORT_BACK_FETCH) {
					reqId, sign, err := t.SignRequestTool()
					if err != nil {
						return "", errors.Wrap(err, "execute worker error")
					}
					fpath, err := t.RetrieveDataFromL2(ctx, NewCessRetrievalRequest(reqId, t.Fid, t.User, time.Second*15, did, sign))
					if err != nil {
						return "", errors.Wrap(err, "execute worker error")
					}
					return fpath, nil
				}

				if Abort(t.FiltePoint, ABORT_JUMP_REQUEST) {
					return "", errors.Wrap(errors.New("abort retrieving data from a peer"), "execute worker error")
				}
				//Retrieve data from a peer Retriever
				fpath, err := t.GetDataFromRemote(did, t.Fid, retriever)
				if err != nil {
					return "", errors.Wrap(err, "execute worker error")
				}
				return fpath, nil
			}, t.Fragments...)
		return fpaths, nil
	}

	if Abort(t.FiltePoint, ABORT_JUMP_REQUEST) {
		return nil, errors.Wrap(errors.New("abort broadcast data retrieval request"), "execute CESS Network data retrieval task error")
	}
	//try to get data from external neighbor nodes
	total := config.FRAGMENTS_NUM + config.PARITY_NUM
	retrievers := t.LoadAllRetrievers(total)
	if len(retrievers) <= 0 {
		return nil, errors.Wrap(errors.New("no retrievers available"), "execute CESS Network data retrieval task error")
	}

	idxCh := make(chan int, total)
	for i := range total {
		idxCh <- i % len(retrievers)
	}
	close(idxCh)

	fpaths := t.BatchExecutor(ctx, len(t.Fragments)-config.PARITY_NUM, func(ctx context.Context, did string) (string, error) {
		idx := <-idxCh
		fpath, err := t.GetDataFromRemote(did, t.Fid, retrievers[idx])
		return fpath, errors.Wrap(err, "execute worker error")
	}, t.Fragments...)
	return fpaths, nil
}

func (t CessRetrievalTask) QueryStorageNodes() ([]string, error) {
	conf := config.GetConfig()
	var nodes []string

	chainId := uint16(conf.ChainId)
	switch chainId {
	case utils.MAINNET_FORMAT, utils.TESTNET_FORMAT:
	default:
		chainId = utils.MAINNET_FORMAT

	}
	fmeta, err := t.cli.QueryFileMetadata(t.Fid, 0)
	if err != nil {
		dealmap, err := t.cli.QueryDealMap(t.Fid, 0)
		if err != nil {
			return nodes, errors.Wrap(err, "query storage nodes error")
		}
		for _, c := range dealmap.CompleteList {
			nodes = append(nodes, utils.EncodePubkey(c.Miner.ToBytes(), chainId))
		}
	} else {
		if len(fmeta.SegmentList) <= 0 {
			err = errors.New("empty segment list")
			return nodes, errors.Wrap(err, "query storage nodes error")
		}
		for _, seg := range fmeta.SegmentList[0].FragmentList {
			nodes = append(nodes, utils.EncodePubkey(seg.Miner.ToBytes(), chainId))
		}
	}
	return nodes, nil
}

func (t CessRetrievalTask) String() string {
	return fmt.Sprintf("[CESS Network Retrieve Task]->{Fid: %s, Segment: %s}", t.Fid, t.Segment)
}
