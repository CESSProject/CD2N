package handles

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/retriever/node"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/gin-gonic/gin"
	"github.com/juju/ratelimit"
)

// Package Access Control
const (
	RETRIEVER_LIMIT = 100
)

type Filter func(user string, dids ...string) int

func (f Filter) Abort(user string, dids ...string) int {
	return f(user, dids...)
}

type retreqCounter struct {
	dids     map[string]struct{}
	Count    *atomic.Int32
	lastTime time.Time
}

type AccessController struct {
	retReqs           *sync.Map
	lock              *sync.RWMutex
	retrievalBucket   *ratelimit.Bucket
	provideDataBucket *ratelimit.Bucket
	claimDataBucket   *ratelimit.Bucket
	window            time.Duration
	bufer, cacher     *buffer.FileBuffer
}

func NewAccessController(window time.Duration, buffer, cacher *buffer.FileBuffer) *AccessController {
	if window <= 0 || window > time.Minute*30 {
		window = time.Minute
	}
	return &AccessController{
		retReqs:           &sync.Map{},
		lock:              &sync.RWMutex{},
		retrievalBucket:   ratelimit.NewBucket(time.Millisecond, 1024),
		provideDataBucket: ratelimit.NewBucket(time.Millisecond, 512),
		claimDataBucket:   ratelimit.NewBucket(time.Millisecond, 512),
	}
}

func (ac *AccessController) UpdateRequestCounter(user, did string) int32 {
	v, ok := ac.retReqs.LoadOrStore(user, &retreqCounter{
		dids:     make(map[string]struct{}),
		Count:    &atomic.Int32{},
		lastTime: time.Now(),
	})
	if ok {
		return 0
	}
	counter, ok := v.(*retreqCounter)
	if !ok || counter == nil {
		return 0
	}
	counter.Count.Add(1)
	counter.dids[did] = struct{}{}
	if time.Since(counter.lastTime) > ac.window {
		ac.lock.Lock()
		if time.Since(counter.lastTime) > ac.window {
			ac.retReqs.Delete(user)
		}
		ac.lock.Unlock()
	}
	return counter.Count.Load()
}

func (ac *AccessController) GetRetrievalToken() bool {
	return ac.retrievalBucket.TakeAvailable(1) >= 1
}

func (ac *AccessController) GetProvideToken() bool {
	return ac.provideDataBucket.TakeAvailable(1) >= 1
}

func (ac *AccessController) GetClaimToken() bool {
	return ac.claimDataBucket.TakeAvailable(1) >= 1
}

func (ac *AccessController) BackFetchFilterFactory() Filter {
	return func(user string, dids ...string) int {
		v, ok := ac.retReqs.Load(user)
		if !ok {
			return node.ABORT_BACK_FETCH
		}
		counter, ok := v.(retreqCounter)
		if !ok {
			return node.ABORT_BACK_FETCH
		}
		if counter.Count.Load() >= 12 ||
			ac.bufer.BufferStatus().Usage <= 0.7 && ac.cacher.BufferStatus().Usage <= 0.7 {
			return 0
		}
		return node.ABORT_BACK_FETCH
	}
}

//	ABORT_JUMP_REQUEST = 2
//	ABORT_BORADCAST    = 1

func (ac *AccessController) JumpRequestFilterFactory() Filter {
	return func(user string, dids ...string) int {
		v, ok := ac.retReqs.Load(user)
		if !ok {
			return node.ABORT_JUMP_REQUEST
		}
		counter, ok := v.(retreqCounter)
		if !ok {
			return node.ABORT_JUMP_REQUEST
		}
		if counter.Count.Load() >= 12 ||
			ac.bufer.BufferStatus().Usage <= 0.6 && ac.cacher.BufferStatus().Usage <= 0.7 {
			return 0
		}
		return node.ABORT_JUMP_REQUEST
	}
}

func (ac *AccessController) BoradcastFilterFactory() Filter {
	return func(user string, dids ...string) int {
		v, ok := ac.retReqs.Load(user)
		if !ok {
			return node.ABORT_BORADCAST
		}
		counter, ok := v.(retreqCounter)
		if !ok {
			return node.ABORT_BORADCAST
		}
		if counter.Count.Load() >= 12 ||
			ac.bufer.BufferStatus().Usage <= 0.5 && ac.cacher.BufferStatus().Usage <= 0.7 {
			return 0
		}
		return node.ABORT_BORADCAST
	}
}

func (ac *AccessController) RetrievalLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ac.GetRetrievalToken() {
			c.AbortWithStatusJSON(429, tsproto.NewResponse(429, "The system is busy, please try again later", nil))
			return
		}
		var req tsproto.CacheRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil || req.UserAddr == "" || (req.Did == "" && req.ExtData == "") {
			c.AbortWithStatusJSON(400, tsproto.NewResponse(400, "The request parameters are incorrect.", nil))
			return
		}
		did := req.ExtData
		if did == "" {
			did = req.Did
		}
		if ac.UpdateRequestCounter(req.UserAddr, did) >= RETRIEVER_LIMIT {
			c.AbortWithStatusJSON(429, tsproto.NewResponse(429, "Too many requests", nil))
			return
		}
		c.Next()
	}
}

func (ac *AccessController) ProvideDataLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ac.GetProvideToken() {
			c.AbortWithStatusJSON(429, tsproto.NewResponse(429, "The system is busy, please try again later", nil))
			return
		}
		c.Next()
	}
}

func (ac *AccessController) ClaimDataLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ac.GetClaimToken() {
			c.AbortWithStatusJSON(429, tsproto.NewResponse(429, "The system is busy, please try again later", nil))
			return
		}
		c.Next()
	}
}
