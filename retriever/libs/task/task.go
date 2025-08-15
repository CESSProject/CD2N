package task

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

const (
	PROVIDE_TASK_GROUP_NUM  = 12
	CALLBACK_CHANNEL_SIZE   = 100000
	TID_BYTES_LEN           = 12
	PROVIDE_TASK_CHECK_TIME = time.Minute * 15
)

type AsyncFinfoBox struct {
	Info     FileInfo `json:"info"`
	NonProxy bool     `json:"non_proxy"`
}

type Task struct {
	Tid       string `json:"tid"`
	Exp       int64  `json:"exp"`
	Acc       string `json:"acc"`
	Addr      string `json:"addr"`
	Did       string `json:"did"`
	ExtData   string `json:"extdata"`
	Timestamp string `json:"timestamp"`
}

type FileInfo struct {
	Fid       string     `json:"fid"`
	FileName  string     `json:"file_name"`
	BaseDir   string     `json:"base_dir"`
	FileSize  int64      `json:"file_size"`
	Owner     []byte     `json:"owner"`
	Territory string     `json:"territory"`
	Segments  []string   `json:"segments"`
	Fragments [][]string `json:"fragments"`
}

type ProvideTask struct {
	Task
	FileInfo
	BitMap    uint16                    `json:"bit_map"`
	WorkDone  bool                      `json:"work_done"`
	GroupSize int                       `json:"group_size"`
	Retry     int                       `json:"retry"`
	SubTasks  map[string]ProvideSubTask `json:"subtasks"`
}

type ProvideSubTask struct {
	Claimant  string `json:"claimant"`
	GroupId   int    `json:"group_id"`
	Index     int    `json:"index"`
	Done      string `json:"done"`
	Timestamp string `json:"timestamp"`
}

type ProvideStat struct {
	Ongoing *atomic.Int64
	Done    *atomic.Int64
	Retried *atomic.Int64
	Fids    *sync.Map
}

type RetrieveTask struct {
	Task
	DataPath  string `json:"data_path"`
	Requester string `json:"requester"`
	Provider  string `json:"provider"`
	Pubkey    []byte `json:"pubkey"`
	RequestId string `json:"request_id"`
	Sign      []byte `json:"sign"`
	RespTime  string `json:"response_time"`
}

func (t RetrieveTask) Marshal() []byte {
	jbytes, _ := json.Marshal(t)
	return jbytes
}

func (t *RetrieveTask) Unmarshal(data []byte) error {
	return json.Unmarshal(data, t)
}

func (t ProvideTask) Marshal() []byte {
	jbytes, _ := json.Marshal(t)
	return jbytes
}

func (t *ProvideTask) Unmarshal(data []byte) error {
	return json.Unmarshal(data, t)
}

func (t *ProvideTask) AddSubTask() int {
	for i := 0; i < 12; i++ {
		if t.BitMap>>i&1 == 0 {
			t.BitMap ^= (1 << i)
			return i
		}
	}
	return -1
}

func (t *ProvideTask) DelSubTask(id int) {
	if id < 0 || id >= PROVIDE_TASK_GROUP_NUM {
		return
	}
	t.BitMap &= ^(1 << id)
}

type EasyKeyLock struct {
	*sync.Map
}

func (kl *EasyKeyLock) Lock(key string) {
	v, _ := kl.LoadOrStore(key, make(chan struct{}, 1))
	ch := v.(chan struct{})
	ch <- struct{}{}
}

func (kl *EasyKeyLock) Unlock(key string) {
	v, ok := kl.Load(key)
	if ok {
		ch := v.(chan struct{})
		<-ch
	}
}

func (kl *EasyKeyLock) RemoveLock(key string) {
	v, ok := kl.Load(key)
	if !ok {
		return
	}
	ch := v.(chan struct{})
	for {
		select {
		case <-ch:
			continue
		default:
			kl.Delete(key)
			return
		}
	}
}

func (ps *ProvideStat) TaskDone(fid string) {
	ps.Done.Add(1)
	ps.Ongoing.Add(-1)
	ps.Retried.Add(-1)
	ps.Fids.Delete(fid)
}

func (ps *ProvideStat) TaskFlash(fid string) {
	if _, ok := ps.Fids.LoadOrStore(fid, struct{}{}); ok {
		ps.Retried.Add(1)
	} else {
		ps.Ongoing.Add(1)
	}
}

func (f FileInfo) String() string {
	jbytes, _ := json.Marshal(f)
	return string(jbytes)
}
