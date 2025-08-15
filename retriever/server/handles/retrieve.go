package handles

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/gateway"
	"github.com/CD2N/CD2N/retriever/node"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/gin-gonic/gin"
	"github.com/ipfs/go-cid"
	"github.com/pkg/errors"
)

func (h *ServerHandle) QueryData(c *gin.Context) {
	did := c.Param("did")
	if did == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "query data error", "bad query params"))
		return
	}
	fpaths, _ := gateway.GetDataFromDiskBuffer(h.buffer, did)
	c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", len(fpaths) > 0))
}

func (h *ServerHandle) FetchCacheData(c *gin.Context) {

	var req tsproto.CacheRequest
	err := c.ShouldBindBodyWithJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "fetch data error", err.Error()))
		return
	}
	if time.Duration(req.Exp) <= 0 || time.Duration(req.Exp) > time.Minute {
		req.Exp = int64(time.Second * 15)
	}

	cessCli, err := h.gateway.GetCessClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "fetch data error", err.Error()))
		return
	}

	fpaths, _ := gateway.GetDataFromDiskBuffer(h.buffer, req.Did)

	if len(fpaths) <= 0 {
		if _, err := cid.Decode(req.Did); err == nil {
			var fpath string
			fpath, err = h.buffer.NewBufPath(req.Did)
			if err != nil {
				c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "fetch data error", err.Error()))
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Exp))
			defer cancel()
			task := node.NewIpfsRetrievalTask(req.Did, req.UserAddr, fpath)
			fpaths, err = h.retr.RetrieveData(ctx, task)
			if err != nil {
				c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "fetch data error", err.Error()))
				return
			}
		} else {
			task := node.NewCesRetrieveTask(cessCli, req.UserAddr, req.ExtData, "", []string{req.Did})
			fpaths, err = h.retr.RetrieveData(
				context.Background(), task,
				h.Ac.BackFetchFilterFactory(),
				h.Ac.JumpRequestFilterFactory(),
				h.Ac.BoradcastFilterFactory(),
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "fetch data error", err.Error()))
				return
			}
		}
		if len(fpaths) <= 0 {
			c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "The specified data was not retrieved", nil))
			return
		}
	}

	if info, err := os.Stat(fpaths[0]); err != nil {
		h.partners.RetrieverSend(req.UserAddr, 0)
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "fetch data error", err.Error()))
		return
	} else {
		if !strings.HasPrefix(req.UserAddr, "0x") {
			req.UserAddr = "0x" + req.UserAddr
		}
		h.partners.RetrieverSend(req.UserAddr, uint64(info.Size()))
	}
	logger.GetLogger(config.LOG_RETRIEVE).Infof("retrieved data: %s, from file %s", req.Did, req.ExtData)
	c.File(fpaths[0])
	h.buffer.AddData(req.Did, fpaths[0])
}

func (h *ServerHandle) ProvideData(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "provide data error", err.Error()))
		return
	}
	if file.Size <= 0 {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "provide data error", "invalid data"))
		return
	}
	metaStr := c.PostForm("metadata")
	if metaStr == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "provide data error", "bad metadata"))
		return
	}
	var meta tsproto.FileMeta
	err = json.Unmarshal([]byte(metaStr), &meta)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "provide data error", err.Error()))
		return
	}
	if meta.Did == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "provide data error", "bad metadata"))
		return
	}
	fpath, err := h.buffer.NewBufPath(meta.Did)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "provide data error", err.Error()))
		return
	}
	err = h.SaveFileToBuf(file, fpath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "provide data error", err.Error()))
		return
	}
	h.buffer.AddData(meta.Did, fpath)
	defer func() {
		if err != nil {
			h.partners.CacherRetrieval(meta.Provider, false)
			h.buffer.RemoveData(fpath)
		}
	}()
	pubkey, err := hex.DecodeString(meta.Key)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "provide data error", err.Error()))
		return
	}
	err = h.node.ReceiveData(context.Background(), meta.Tid, meta.Provider, fpath, pubkey)
	if err != nil {
		logger.GetLogger(config.LOG_RETRIEVE).Error(err)
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "provide data error", err.Error()))
		return
	}
	h.partners.CacherRetrieval(meta.Provider, true)
	c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", nil))
}

func (h *ServerHandle) QueryCacheCap(c *gin.Context) {
	user := c.Param("addr")
	if user == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "check cache order error", "bad request params"))
		return
	}
	u, _ := url.JoinPath(h.teeEndpoint, "download_traffic_query")
	log.Println(u)
	ccap, err := tsproto.QueryRemainCap(u, user)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "query cache cap", err.Error()))
		return
	}
	c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", ccap))
}

func (h *ServerHandle) SaveFileToBuf(file *multipart.FileHeader, fpath string) error {
	src, err := file.Open()
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	defer src.Close()

	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	err = f.Sync()
	return errors.Wrap(err, "cache file error")
}

func (h *ServerHandle) SaveDataToBuf(src io.Reader, fpath string) error {

	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return errors.Wrap(err, "cache file error")
}
