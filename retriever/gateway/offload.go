package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/pkg/errors"
)

type DataUnit struct {
	Did  string
	Path string
}

func (g *Gateway) BatchOffloadingWithFileInfo(info task.FileInfo) error {
	//create date units
	for _, s := range info.Fragments {
		for _, f := range s {
			select {
			case g.offloadingQueue <- DataUnit{
				Did:  f,
				Path: path.Join(info.BaseDir, f),
			}:
			default:
			}
		}
	}
	if err := g.publishOffloadingTask(); err != nil {
		return errors.Wrap(err, "offloading data error")
	}
	return nil
}

func (g *Gateway) BatchOffloadingWithPaths(paths []string) error {

	for _, p := range paths {
		select {
		case g.offloadingQueue <- DataUnit{
			Did:  path.Base(p),
			Path: p,
		}:
		default:
		}
	}
	if err := g.publishOffloadingTask(); err != nil {
		return errors.Wrap(err, "offloading data error")
	}

	return nil
}

func (g *Gateway) publishOffloadingTask() error {
	rand, _ := utils.GetRandomBytes()
	conf := config.GetConfig()
	task := task.Task{
		Tid:       hex.EncodeToString(rand[:task.TID_BYTES_LEN]),
		Exp:       int64(time.Second * 15),
		Acc:       g.contract.Node.Hex(),
		Addr:      conf.Endpoint,
		Timestamp: time.Now().Format(config.TIME_LAYOUT),
	}
	return client.PublishMessage(g.redisCli, context.Background(), client.CHANNEL_DATA_OFFLOAD, task)
}

func (g *Gateway) ClaimDataFromOffloadingQueue() (DataUnit, error) {
	for {
		select {
		case u := <-g.offloadingQueue:
			if _, err := os.Stat(u.Path); err != nil {
				continue
			}
			return u, nil
		default:
			return DataUnit{}, errors.New("offload queue is empty now")
		}
	}
}

func (g *Gateway) ClaimOffloadingData(req tsproto.FileRequest) (DataUnit, error) {
	var u DataUnit
	sign, err := hex.DecodeString(req.Sign)
	if err != nil {
		return u, errors.Wrap(err, "claim offloading data error")
	}
	date, err := time.Parse(config.TIME_LAYOUT, req.Timestamp)
	if err != nil {
		return u, errors.Wrap(err, "claim offloading data error")
	}
	if time.Since(date) > time.Second*15 {
		return u, errors.Wrap(errors.New("expired request"), "claim offloading data error")
	}
	req.Sign = ""
	jbytes, err := json.Marshal(req)
	if err != nil {
		return u, errors.Wrap(err, "claim offloading data error")
	}
	if !utils.VerifySecp256k1Sign(req.Pubkey, jbytes, sign) {
		return u, errors.Wrap(errors.New("signature verification failed"), "claim offloading data error")
	}
	u, err = g.ClaimDataFromOffloadingQueue()
	if err != nil {
		return u, errors.Wrap(err, "claim offloading data error")
	}
	return u, nil
}
