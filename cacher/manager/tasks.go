package manager

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/CD2N/CD2N/cacher/config"
	"github.com/CESSProject/go-sdk/chain/evm"
	"github.com/CESSProject/go-sdk/logger"
	"github.com/go-redis/redis/v8"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

const (
	DEFAULT_TASK_CHANNEL_SIZE = 10240
	TIME_LAYOUT               = "2006/01/02 15:04:05"
)

type Event interface {
	Status() int
	Result() any
	Error() error
}

type Callback func(Event)

type Executor interface {
	Execute(task Task) error
}

type Task struct {
	Tid       string `json:"tid"`       //Task ID
	Channel   string `json:"channel"`   //The channel from which the task came
	Exp       int64  `json:"exp"`       //Expiration time
	Acc       string `json:"acc"`       //Task initiator account
	Addr      string `json:"addr"`      //Task initiator access address
	Did       string `json:"did"`       //Data ID
	ExtData   string `json:"extdata"`   //Additional data
	Timestamp string `json:"timestamp"` //Task timestamp
}

type TaskDispatcher struct {
	*RetrieverManager
	channels  []string
	executors map[string]Executor
	lock      *sync.RWMutex
	taskCh    chan *redis.Message
	pool      *ants.Pool
}

func NewTaskDispatcher(wqLen int) (*TaskDispatcher, error) {
	if wqLen <= 0 || wqLen > 1024 {
		wqLen = 1024
	}
	pool, err := ants.NewPool(128)
	if err != nil {
		return nil, errors.Wrap(err, "new task dispatcher error")
	}
	return &TaskDispatcher{
		RetrieverManager: NewRetrieverManager(),
		executors:        make(map[string]Executor),
		lock:             &sync.RWMutex{},
		taskCh:           make(chan *redis.Message, wqLen),
		pool:             pool,
	}, nil
}

func (td *TaskDispatcher) RegisterTaskExecutor(channel string, executor Executor) {
	td.lock.Lock()
	defer td.lock.Unlock()
	_, ok := td.executors[channel]
	if !ok {
		td.channels = append(td.channels, channel)
	}
	td.executors[channel] = executor
}

func (td *TaskDispatcher) SubscribeTasksFromRetrievers(ctx context.Context, contract *evm.CacheProtoContract, interval time.Duration, redisAcc, redisPwd string) {
	if interval <= 0 || interval > time.Hour*24 {
		interval = time.Minute * 60
	}
	ticker := time.NewTicker(interval)
	conf := config.GetConfig()
	for {
		if err := td.LoadRetrievers(contract, conf, redisAcc, redisPwd); err != nil {
			time.Sleep(time.Minute * 2)
			continue
		}
		td.SubscribeRetrievers(ctx, td.taskCh, td.channels...)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}

}

func (td *TaskDispatcher) TaskDispatch(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case task := <-td.taskCh:
			var taskPld Task
			logger.GetLogger(config.LOG_TASK).Infof("subscribe task from channel: %s", task.Channel)
			err := json.Unmarshal([]byte(task.Payload), &taskPld)
			if err != nil {
				logger.GetLogger(config.LOG_TASK).Error(err.Error())
				continue
			}
			td.lock.RLock()
			exector, ok := td.executors[task.Channel]
			td.lock.RUnlock()
			if !ok {
				logger.GetLogger(config.LOG_TASK).Error("task: ", task.Payload, " from channel ", task.Channel, ", no task executor was matched")
				continue
			}
			taskPld.Channel = task.Channel
			if err = td.pool.Submit(func() {
				if err := exector.Execute(taskPld); err != nil {
					logger.GetLogger(config.LOG_TASK).Error(" execute task error: ", err.Error())
				}
			}); err != nil {
				logger.GetLogger(config.LOG_TASK).Error(err.Error())
			}
		}
	}
}
