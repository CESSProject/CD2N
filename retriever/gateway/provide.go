package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/CD2N/CD2N/sdk/sdkgo/retriever"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

type FileRequest struct {
	Pubkey    []byte `json:"pubkey"`
	Fid       string `json:"fid"`
	Timestamp string `json:"timestamp"`
	Sign      string `json:"sign"`
}

type FileResponse struct {
	Fid       string   `json:"fid"`
	Fragments []string `json:"fragments"`
	Token     string   `json:"token"`
}

type Statistics interface {
	StatTimes(id string)
}

func (g *Gateway) ProvideFile(ctx context.Context, buffer *buffer.FileBuffer, exp time.Duration, info task.FileInfo, nonProxy bool) error {
	if _, ok := g.pstats.Fids.LoadOrStore(info.Fid, struct{}{}); ok {
		return errors.Wrap(errors.New("file is being processed"), "provide file error")
	}

	rand, _ := utils.GetRandomBytes()
	conf := config.GetConfig()
	ftask := task.Task{
		Tid:       hex.EncodeToString(rand[:task.TID_BYTES_LEN]),
		Exp:       int64(exp),
		Acc:       g.contract.Node.Hex(),
		Addr:      conf.Endpoint,
		Did:       info.Fid,
		Timestamp: time.Now().Format(config.TIME_LAYOUT),
	}
	provideTask := task.ProvideTask{
		Task:      ftask,
		FileInfo:  info,
		GroupSize: len(info.Fragments),
		SubTasks:  make(map[string]task.ProvideSubTask),
	}
	var (
		hash string
		err  error
	)
	defer func() {
		if err != nil {
			g.pstats.Fids.Delete(info.Fid)
			TaskGc(buffer, provideTask)
		}
	}()
	if !nonProxy {
		hash, err = g.CreateStorageOrder(info)
		if err != nil {
			logger.GetLogger(config.LOG_PROVIDER).Error(errors.Wrap(err, "provide file error "), ", tx hash: ", hash)
			return errors.Wrap(err, "provide file error")
		} else {
			logger.GetLogger(config.LOG_PROVIDER).Infof("create storage order for file %s, tx hash is %s \n", info.Fid, hash)
		}
	}

	cli, err := g.GetCessClient()
	if err != nil {
		return errors.Wrap(err, "provide file error")
	}
	if meta, err := cli.QueryFileMetadata(info.Fid, 0); err == nil && len(meta.Owner) > 0 {
		g.pstats.Fids.Delete(info.Fid)
		TaskGc(buffer, provideTask)
		logger.GetLogger(config.LOG_PROVIDER).Infof("file %s completed flash transfer", info.Fid)
		return nil
	}

	if err = g.PutProvideTask(info.Fid, provideTask); err != nil {
		return errors.Wrap(err, "provide file error")
	}

	if err = client.PublishMessage(g.redisCli, ctx, client.CHANNEL_PROVIDE, ftask); err != nil {
		return errors.Wrap(err, "provide file error")
	}
	g.pstats.Ongoing.Add(1)
	return nil
}

func (g *Gateway) ClaimFile(ctx context.Context, req tsproto.FileRequest) (FileResponse, error) {
	var resp FileResponse
	sign, err := hex.DecodeString(req.Sign)
	if err != nil {
		return resp, errors.Wrap(err, "claim file error")
	}
	date, err := time.Parse(config.TIME_LAYOUT, req.Timestamp)
	if err != nil {
		return resp, errors.Wrap(err, "claim file error")
	}
	if time.Since(date) > time.Second*15 {
		return resp, errors.Wrap(errors.New("expired request"), "claim file error")
	}
	req.Sign = ""
	jbytes, err := json.Marshal(req)
	if err != nil {
		return resp, errors.Wrap(err, "claim file error")
	}
	if !utils.VerifySecp256k1Sign(req.Pubkey, jbytes, sign) {
		return resp, errors.Wrap(errors.New("signature verification failed"), "claim file error")
	}

	if _, ok := g.pstats.Fids.Load(req.Fid); !ok {
		return resp, errors.Wrap(errors.New("the file has been distributed"), "claim file error")
	}

	g.keyLock.Lock(req.Fid)
	var ftask task.ProvideTask
	if err = g.GetProvideTask(req.Fid, &ftask); err != nil {
		g.keyLock.Delete(req.Fid) // task done, remove the key-value lock
		return resp, errors.Wrap(err, "claim file error")
	}
	defer g.keyLock.Unlock(req.Fid)
	if len(ftask.SubTasks) == task.PROVIDE_TASK_GROUP_NUM {
		return resp, errors.Wrap(errors.New("file be claimed"), "claim file error")
	}
	gid := ftask.AddSubTask()
	if gid == -1 {
		return resp, errors.Wrap(errors.New("all subtasks have been distributed"), "claim file error")
	}

	key, err := crypto.DecompressPubkey(req.Pubkey)
	if err != nil {
		return resp, errors.Wrap(err, "claim file error")
	}
	for {
		token, _ := utils.GetRandomBytes()
		resp.Token = hex.EncodeToString(token[:task.TID_BYTES_LEN])
		if _, ok := ftask.SubTasks[resp.Token]; !ok {
			break
		}
	}
	ftask.SubTasks[resp.Token] = task.ProvideSubTask{
		Claimant:  crypto.PubkeyToAddress(*key).Hex(),
		GroupId:   gid,
		Timestamp: time.Now().Format(config.TIME_LAYOUT),
	}
	resp.Fragments = make([]string, 0, ftask.GroupSize)
	for i := 0; i < ftask.GroupSize; i++ {
		resp.Fragments = append(resp.Fragments, ftask.Fragments[i][gid])
	}
	resp.Fid = req.Fid
	// err = client.PutData(g.taskRecord, req.Fid, ftask)
	if err = g.PutProvideTask(req.Fid, ftask); err != nil {
		return resp, errors.Wrap(err, "claim file error")
	}
	return resp, nil
}

func (g *Gateway) FetchFile(ctx context.Context, fid, did, token string) (string, error) {
	var fpath string
	if _, ok := g.pstats.Fids.LoadOrStore(fid, struct{}{}); !ok {
		return fpath, errors.Wrap(errors.New("wrong file id"), "fetch file error")
	}
	g.keyLock.Lock(fid)
	defer g.keyLock.Unlock(fid)
	var task task.ProvideTask
	if err := g.GetProvideTask(fid, &task); err != nil {
		return fpath, errors.Wrap(err, "fetch file error")
	}
	subTask, ok := task.SubTasks[token]
	if !ok {
		return fpath, errors.Wrap(errors.New("subtask not found"), "fetch file error")
	}
	if subTask.Index == task.GroupSize {
		return fpath, errors.Wrap(errors.New("subtask done"), "fetch file error")
	}
	fpath = filepath.Join(task.BaseDir, task.Fragments[subTask.Index][subTask.GroupId])
	if _, err := os.Stat(fpath); err != nil {
		return fpath, errors.Wrap(errors.New("the data has expired"), "fetch file error")
	}
	subTask.Index++
	task.SubTasks[token] = subTask
	if err := g.PutProvideTask(fid, task); err != nil {
		return fpath, errors.Wrap(err, "fetch file error")
	}
	return fpath, nil
}

func (g *Gateway) ProvideTaskChecker(ctx context.Context, buffer *buffer.FileBuffer, stat Statistics) error {
	ticker := time.NewTicker(task.PROVIDE_TASK_CHECK_TIME)
	for {
		select {
		case <-ticker.C:
			if err := g.checker(ctx, buffer, stat); err != nil {
				logger.GetLogger(config.LOG_PROVIDER).Error(err)
			}
		case <-ctx.Done():
			return errors.New("provide task checker done.")
		}
	}
}

func (g *Gateway) checker(ctx context.Context, buffer *buffer.FileBuffer, stat Statistics) error {
	keys, err := client.GetKeysByPrefix(g.redisCli, fmt.Sprintf("%s-ftask_key-", g.nodeAcc))
	if err != nil {
		return errors.Wrap(err, "check provide task error")
	}
	for _, key := range keys {
		select {
		case <-ctx.Done():
		default:
		}
		if err := func(key string) error {
			select {
			case <-ctx.Done():
			default:
			}
			var ftask task.ProvideTask
			fid, _ := strings.CutPrefix(key, fmt.Sprintf("%s-ftask_key-", g.nodeAcc))
			if strings.Contains(fid, config.DB_SEGMENT_PREFIX) {
				return nil
			}
			g.keyLock.Lock(fid)
			defer g.keyLock.Unlock(fid)
			if err := g.GetProvideTask(fid, &ftask); err != nil {
				return err
			}

			gcflag := TaskNeedToBeGC(ftask)
			if ftask.WorkDone || gcflag {
				if gcflag {
					TaskGc(buffer, ftask)
					logger.GetLogger(config.LOG_PROVIDER).Infof("file %s expires and task is collected. \n", fid)
				} else {
					logger.GetLogger(config.LOG_PROVIDER).Infof("file %s distribute workflow done. \n", fid)
				}
				g.pstats.TaskDone(fid)
				g.keyLock.RemoveLock(fid)
				client.DeleteMessage(g.redisCli, context.Background(), key)
				return nil
			}
			done := 0
			cli, err := g.GetCessClient()
			if err != nil {
				logger.GetLogger(config.LOG_PROVIDER).Error(err)
				return nil
			}
			cmpSet, err := retriever.QueryDealMap(cli, fid)
			if err == nil {
				for k, v := range ftask.SubTasks {
					if _, ok := cmpSet[v.GroupId+1]; v.Index == ftask.GroupSize && ok {
						v.Done = time.Now().Format(config.TIME_LAYOUT)
						done++
						ftask.SubTasks[k] = v
						RemoveSubTaskFiles(buffer, v.GroupId, ftask)
						continue
					}
					upt, err := time.Parse(config.TIME_LAYOUT, v.Timestamp)
					if err != nil {
						continue
					}
					if time.Since(upt) >= task.PROVIDE_TASK_CHECK_TIME*2 {
						if stat != nil {
							stat.StatTimes(v.Claimant)
						}
						logger.GetLogger(config.LOG_PROVIDER).Infof("remove subtask %d of file %s, timeout!", v.GroupId+1, fid)
						ftask.DelSubTask(v.GroupId)
						delete(ftask.SubTasks, k)
					}
				}
			} else if strings.Contains(err.Error(), "data not found") {
				logger.GetLogger(config.LOG_PROVIDER).Infof("file %s data distribution completed.", fid)
				done = task.PROVIDE_TASK_GROUP_NUM
			} else {
				logger.GetLogger(config.LOG_PROVIDER).Error(err)
				return nil
			}

			if done == task.PROVIDE_TASK_GROUP_NUM {
				logger.GetLogger(config.LOG_PROVIDER).Infof("file %s be distributed done. \n", fid)
				ftask.WorkDone = true
			} else if len(ftask.SubTasks) < task.PROVIDE_TASK_GROUP_NUM {
				err := client.PublishMessage(g.redisCli, ctx, client.CHANNEL_PROVIDE, ftask.Task)
				if err == nil {
					ftask.Retry += 1
					g.pstats.TaskFlash(fid)
					logger.GetLogger(config.LOG_PROVIDER).Infof("redistribute file %s. \n", fid)
				} else {
					logger.GetLogger(config.LOG_PROVIDER).Error(err)
				}
			}
			if err := g.PutProvideTask(fid, ftask); err != nil {
				logger.GetLogger(config.LOG_PROVIDER).Error(err)
				return nil
			}
			if done == task.PROVIDE_TASK_GROUP_NUM {
				//remove fid from provide task stats
				g.pstats.Fids.Delete(fid)
			}
			return nil
		}(key); err != nil {
			return errors.Wrap(err, "check provide task error")
		}
	}
	return nil
}

// func (g *Gateway) checker2(ctx context.Context, buffer *buffer.FileBuffer, stat Statistics) error {
// 	err := client.DbIterator(g.taskRecord,
// 		func(key []byte) error {
// 			select {
// 			case <-ctx.Done():
// 			default:
// 			}
// 			var ftask task.ProvideTask
// 			fid := string(key)
// 			if strings.Contains(fid, config.DB_SEGMENT_PREFIX) {
// 				return nil
// 			}
// 			g.keyLock.Lock(fid)
// 			defer g.keyLock.Unlock(fid)
// 			if err := client.GetData(g.taskRecord, fid, &ftask); err != nil {
// 				return err
// 			}

// 			gcflag := TaskNeedToBeGC(ftask)
// 			if ftask.WorkDone || gcflag {
// 				if gcflag {
// 					TaskGc(buffer, ftask)
// 					logger.GetLogger(config.LOG_PROVIDER).Infof("file %s expires and task is collected. \n", fid)
// 				} else {
// 					logger.GetLogger(config.LOG_PROVIDER).Infof("file %s distribute workflow done. \n", fid)
// 				}
// 				g.pstats.TaskDone(fid)
// 				g.keyLock.RemoveLock(fid)
// 				client.DeleteData(g.taskRecord, fid)

// 				return nil
// 			}
// 			done := 0
// 			cli, err := g.GetCessClient()
// 			if err != nil {
// 				logger.GetLogger(config.LOG_PROVIDER).Error(err)
// 				return nil
// 			}
// 			cmpSet, err := retriever.QueryDealMap(cli, fid)
// 			if err == nil {
// 				for k, v := range ftask.SubTasks {
// 					if _, ok := cmpSet[v.GroupId+1]; v.Index == ftask.GroupSize && ok {
// 						v.Done = time.Now().Format(config.TIME_LAYOUT)
// 						done++
// 						ftask.SubTasks[k] = v
// 						RemoveSubTaskFiles(buffer, v.GroupId, ftask)
// 						continue
// 					}
// 					upt, err := time.Parse(config.TIME_LAYOUT, v.Timestamp)
// 					if err != nil {
// 						continue
// 					}
// 					if time.Since(upt) >= task.PROVIDE_TASK_CHECK_TIME*2 {
// 						if stat != nil {
// 							stat.StatTimes(v.Claimant)
// 						}
// 						logger.GetLogger(config.LOG_PROVIDER).Infof("remove subtask %d of file %s, timeout!", v.GroupId+1, fid)
// 						ftask.DelSubTask(v.GroupId)
// 						delete(ftask.SubTasks, k)
// 					}
// 				}
// 			} else if strings.Contains(err.Error(), "data not found") {
// 				logger.GetLogger(config.LOG_PROVIDER).Infof("file %s data distribution completed.", fid)
// 				done = task.PROVIDE_TASK_GROUP_NUM
// 			} else {
// 				logger.GetLogger(config.LOG_PROVIDER).Error(err)
// 				return nil
// 			}

// 			if done == task.PROVIDE_TASK_GROUP_NUM {
// 				logger.GetLogger(config.LOG_PROVIDER).Infof("file %s be distributed done. \n", fid)
// 				ftask.WorkDone = true
// 			} else if len(ftask.SubTasks) < task.PROVIDE_TASK_GROUP_NUM {
// 				err := client.PublishMessage(g.redisCli, ctx, client.CHANNEL_PROVIDE, ftask.Task)
// 				if err == nil {
// 					ftask.Retry += 1
// 					g.pstats.TaskFlash(fid)
// 					logger.GetLogger(config.LOG_PROVIDER).Infof("redistribute file %s. \n", fid)
// 				} else {
// 					logger.GetLogger(config.LOG_PROVIDER).Error(err)
// 				}
// 			}
// 			if err := client.PutData(g.taskRecord, fid, ftask); err != nil {
// 				logger.GetLogger(config.LOG_PROVIDER).Error(err)
// 				return nil
// 			}
// 			if done == task.PROVIDE_TASK_GROUP_NUM {
// 				//remove fid from provide task stats
// 				g.pstats.Fids.Delete(fid)
// 			}
// 			return nil
// 		},
// 	)
// 	return errors.Wrap(err, "check provide task error")
// }

func RemoveSubTaskFiles(buffer *buffer.FileBuffer, groupId int, ftask task.ProvideTask) error {
	for i := range ftask.Fragments {
		err := buffer.RemoveData(filepath.Join(ftask.BaseDir, ftask.Fragments[i][groupId]))
		if err != nil {
			return err
		}
	}
	if entries, err := os.ReadDir(ftask.BaseDir); err != nil || len(entries) == 0 {
		os.RemoveAll(ftask.BaseDir)
	}
	return nil
}

func TaskNeedToBeGC(ftask task.ProvideTask) bool {
	t, err := time.Parse(config.TIME_LAYOUT, ftask.Timestamp)
	if err == nil && time.Since(t) > time.Hour*24*3 {
		return true
	}
	for _, v := range ftask.SubTasks {
		if v.Index < ftask.GroupSize {
			fpath := filepath.Join(ftask.BaseDir, ftask.Fragments[v.Index][v.GroupId])
			if _, err := os.Stat(fpath); err != nil {
				return true
			}
		}
	}
	return false
}

func TaskGc(buffer *buffer.FileBuffer, ftask task.ProvideTask) {
	for i := range ftask.Fragments {
		for j := range ftask.Fragments[i] {
			fpath := filepath.Join(ftask.BaseDir, ftask.Fragments[i][j])
			buffer.RemoveData(fpath)
		}
	}
	if entries, err := os.ReadDir(ftask.BaseDir); err != nil || len(entries) == 0 {
		os.RemoveAll(ftask.BaseDir)
	}
}

func (g *Gateway) GetCessClient() (*chain.Client, error) {
	if g.cessCli != nil {
		if _, err := g.cessCli.QueryBlockNumber(""); err == nil {
			return g.cessCli, nil
		}
		if err := g.cessCli.RefreshSubstrateApi(true); err != nil {
			return nil, errors.Wrap(err, "get cess client error")
		}
		return g.cessCli, nil
	}
	conf := config.GetConfig()
	cli, err := chain.NewLightCessClient(conf.Mnemonic, conf.Rpcs)
	if err != nil {
		return nil, errors.Wrap(err, "get cess client error")
	}
	g.cessCli = cli
	return cli, nil
}
