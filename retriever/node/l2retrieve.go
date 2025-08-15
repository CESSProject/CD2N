package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/pkg/errors"
)

type L2Retriever interface {
	GetRetrieveTask(ctx context.Context, tid string) (task.RetrieveTask, error)
	ReceiveData(ctx context.Context, tid, provider, fpath string, pubkey []byte) error
	RetrieveDataFromL2(ctx context.Context, req RetrievalRequest) (string, error)
}

type RetrievalRequest struct {
	ReqId   string
	Channel string
	Did     string
	ExtData string
	User    string
	Exp     time.Duration
	Sign    []byte
}

func NewRetrievalRequest(reqId, extdata, user string, exp time.Duration, did string, sign []byte) RetrievalRequest {
	return RetrievalRequest{
		ReqId:   reqId,
		User:    user,
		Did:     did,
		Exp:     exp,
		Sign:    sign,
		ExtData: extdata,
	}
}

func NewCessRetrievalRequest(reqId, extdata, user string, exp time.Duration, did string, sign []byte) RetrievalRequest {
	req := NewRetrievalRequest(reqId, extdata, user, exp, did, sign)
	req.Channel = client.CHANNEL_RETRIEVE
	return req
}

func NewIpfsRetrievalRequest(reqId, extdata, user string, exp time.Duration, did string, sign []byte) RetrievalRequest {
	req := NewRetrievalRequest(reqId, extdata, user, exp, did, sign)
	req.Channel = client.CHANNEL_IPFS_RETRIEVE
	return req
}

func (mg *Manager) GetRetrieveTask(ctx context.Context, tid string) (task.RetrieveTask, error) {
	var rtask task.RetrieveTask
	data := client.GetMessage(mg.redisCli, ctx, tid)
	if len(data) == 0 {
		return rtask, errors.Wrap(errors.New("empty data"), "get retrieve task error")
	}
	err := json.Unmarshal(data, &rtask)
	if err != nil {
		return rtask, errors.Wrap(err, "get retrieve task error")
	}
	return rtask, nil
}

func (mg *Manager) RetrieveData(ctx context.Context, req RetrievalRequest) (string, error) {
	//publish retrieve data task
	mg.retrieveNum.Add(1)
	ch, err := mg.NewRetrieveTask(ctx, req)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data error")
	}
	timer := time.NewTimer(req.Exp)
	select {
	case <-ctx.Done():
		return "", errors.Wrap(ctx.Err(), "retrieve data error")
	case <-timer.C:
		return "", errors.Wrap(errors.New("task timeout"), "retrieve data error")
	case tid := <-ch:
		mg.retrievedNum.Add(1)
		return tid, nil
	}
}

func (mg *Manager) ReceiveData(ctx context.Context, tid, provider, fpath string, pubkey []byte) error {
	ok, err := client.SetNxMessage(mg.redisCli, ctx, tid+"-dlock", []byte{}, time.Millisecond*200)
	if err != nil {
		return errors.Wrap(err, "receive data error")
	}
	if !ok {
		return errors.Wrap(fmt.Errorf("task %s is occupied", tid), "receive data error")
	}
	task, err := mg.GetRetrieveTask(ctx, tid)
	if err != nil {
		return errors.Wrap(err, "receive data error")
	}
	task.Provider = provider
	task.Pubkey = pubkey
	task.DataPath = fpath
	task.RespTime = time.Now().Format(config.TIME_LAYOUT)
	err = client.SetMessage(mg.redisCli, ctx, tid, task.Marshal(), time.Duration(task.Exp))
	if err != nil {
		return errors.Wrap(err, "receive data error")
	}

	logger.GetLogger(config.LOG_RETRIEVE).Infof("receive data %s, from file %s ,task id: %s", task.Did, task.ExtData, tid)
	mg.callbackCh <- tid
	return nil
}

func (mg *Manager) NewRetrieveTask(ctx context.Context, req RetrievalRequest) (chan string, error) {
	ch := make(chan string, 1)
	task := NewRetrieveTask(req.Did, req.User, mg.nodeAddr, req.ReqId, req.ExtData, int64(req.Exp), req.Sign)
	err := client.SetMessage(mg.redisCli, ctx, task.Tid, task.Marshal(), req.Exp)
	if err != nil {
		return nil, errors.Wrap(err, "new retrieve data task error")
	}
	err = client.PublishMessage(mg.redisCli, ctx, req.Channel, task.Task)
	if err != nil {
		return nil, errors.Wrap(err, "new retrieve data task error")
	}
	logger.GetLogger(config.LOG_RETRIEVE).Infof("new retrieve data task %s for fragment %s, from file %s", task.Tid, req.Did, req.ExtData)
	mg.rw.Lock()
	defer mg.rw.Unlock()
	mg.rtasks[task.Tid] = ch
	return ch, nil
}

func (mg *Manager) NewRetrieveDataTask(ctx context.Context, did, requester, reqId, extdata string, exp time.Duration, sign []byte) (chan string, error) {
	ch := make(chan string, 1)
	task := NewRetrieveTask(did, requester, mg.nodeAddr, reqId, extdata, int64(exp), sign)
	err := client.SetMessage(mg.redisCli, ctx, task.Tid, task.Marshal(), exp)
	if err != nil {
		return nil, errors.Wrap(err, "new retrieve data task error")
	}
	err = client.PublishMessage(mg.redisCli, ctx, client.CHANNEL_RETRIEVE, task.Task)
	if err != nil {
		return nil, errors.Wrap(err, "new retrieve data task error")
	}
	logger.GetLogger(config.LOG_RETRIEVE).Infof("new retrieve data task %s for fragment %s, from file %s", task.Tid, did, extdata)
	mg.rw.Lock()
	defer mg.rw.Unlock()
	mg.rtasks[task.Tid] = ch
	return ch, nil
}

func (mg *Manager) CallbackManager(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case tid := <-mg.callbackCh:
			mg.rw.RLock()
			signal := mg.rtasks[tid]
			delete(mg.rtasks, tid)
			signal <- tid
			close(signal)
			mg.rw.RUnlock()
		}
	}
}

func NewRetrieveTask(did, reqer, acc, reqId, extdata string, exp int64, sign []byte) task.RetrieveTask {
	rand, _ := utils.GetRandomBytes()
	conf := config.GetConfig()
	return task.RetrieveTask{
		Task: task.Task{
			Tid:       hex.EncodeToString(rand[:task.TID_BYTES_LEN]),
			Exp:       exp,
			Acc:       acc,
			Addr:      conf.Endpoint,
			Did:       did,
			ExtData:   extdata,
			Timestamp: time.Now().Format(config.TIME_LAYOUT),
		},
		Requester: reqer,
		RequestId: reqId,
		Sign:      sign,
	}
}

func (mg *Manager) RetrieveDataFromL2(ctx context.Context, req RetrievalRequest) (string, error) {

	u, err := url.JoinPath(mg.teeEndpoint, tsproto.AUDIT_DATA_URL)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data from l2 cache network error")
	}

	tid, err := mg.RetrieveData(ctx, req)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data from l2 cache network error")
	}
	task, err := mg.GetRetrieveTask(ctx, tid)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data from l2 cache network error")
	}
	rpath, err := mg.databuf.NewBufPath(task.Did)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data from l2 cache network error")
	}
	if req.User == "" {
		req.User = utils.Remove0x(mg.nodeAddr)
	} else {
		req.User = utils.Remove0x(req.User)
	}
	if len(task.Pubkey) > 0 {
		tidBytes, _ := hex.DecodeString(tid)
		if err = tsproto.AuditData(u, task.DataPath, rpath, tsproto.TeeReq{
			Cid:         req.Did,
			UserAcc:     req.User,
			Key:         task.Pubkey,
			Nonce:       tidBytes,
			RequestId:   req.ReqId,
			UserSign:    req.Sign,
			SupplierAcc: task.Provider,
		}); err != nil {
			return "", errors.Wrap(err, "retrieve data from l2 cache network error")
		}
	} else {
		rpath = task.DataPath
	}
	mg.databuf.AddData(task.Did, rpath)
	return rpath, nil
}
