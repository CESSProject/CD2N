package handles

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/gateway"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func (h *ServerHandle) DownloadUserFile(c *gin.Context) {
	var targetPath string
	if !config.GetConfig().DisableLocalSvc {
		targetPath = c.Param("target")
	}
	fid := c.Param("fid")
	if fid == "" {
		c.JSON(http.StatusBadRequest,
			tsproto.NewResponse(http.StatusBadRequest, "download file error", "bad file id"))
		return
	}
	segment := c.Param("segment")
	key := segment
	if key == "" {
		key = fid
	}
	err := h.gateway.WaitFileCache(key, time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
		return
	}

	defer h.gateway.ReleaseCacheTask(key)

	fileRange := c.Request.Header.Get("Range")
	capsule := c.GetHeader("Capsule")
	rkb := c.GetHeader("Rkb")
	pkX := c.GetHeader("Pkx")

	info, err := h.gateway.RetrieveDataFromCache(fid, key, segment, fileRange)
	if err != nil {
		info, err = h.gateway.DownloadData(context.Background(), h.buffer, h.retr, fid, segment, fileRange)
		if err != nil {
			c.JSON(http.StatusInternalServerError,
				tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
			return
		}
		logger.GetLogger(config.LOG_GATEWAY).Infof("get file %s from CD2N network", fid)
	} else {
		logger.GetLogger(config.LOG_GATEWAY).Infof("get file %s from local disk cache", key)
	}

	h.gateway.ReleaseCacheTask(key) //allows repeated calls to minimize key usage

	if rkb != "" && pkX != "" {
		dpath, err := h.buffer.NewBufPath(
			hex.EncodeToString(
				utils.CalcSha256Hash([]byte(info.Fid), []byte(info.Path), []byte("decrypt")),
			),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError,
				tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
			return
		}
		defer os.Remove(dpath)
		pubkeyX, err := utils.ParsingPublickey(pkX)
		if err != nil {
			c.JSON(http.StatusInternalServerError,
				tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
			return
		}
		if err := h.gateway.DecryptData(&info, []byte(capsule), []byte(rkb), pubkeyX, dpath); err != nil {
			c.JSON(http.StatusInternalServerError,
				tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
		}
	}

	err = ServeFileWithDataInfo(c, info, targetPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
	}
}

func ServeFileWithDataInfo(c *gin.Context, info gateway.DataInfo, targetPath string) error {
	fpath := info.Path
	if info.DecryptedFilePath != "" {
		fpath = info.DecryptedFilePath
	}
	if targetPath != "" {
		return errors.Wrap(utils.CopyFile(fpath, targetPath), "serve file error")
	}
	if info.End-info.Start > 0 {
		logger.GetLogger(config.LOG_GATEWAY).Infof("serve file %s for range request, range: %d-%d", info.Fid, info.Start, info.End)
		err := RangeResponse(c, info.Start, info.End, info.Name, fpath)
		return errors.Wrap(err, "serve file error")
	}
	logger.GetLogger(config.LOG_GATEWAY).Infof("serve file %s", fpath)
	c.FileAttachment(fpath, info.Name)
	return nil
}

func RangeResponse(c *gin.Context, start, end int64, name, fpath string) error {
	file, err := os.Open(fpath)
	if err != nil {
		return errors.Wrap(err, "file range request error")
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return errors.Wrap(err, "file range request error")
	}
	if end <= 0 || end > stat.Size() {
		end = stat.Size()
	}
	mime := make([]byte, 512)
	_, err = file.Read(mime)
	if err != nil {
		return errors.Wrap(err, "file range request error")
	}
	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, stat.Size()))
	c.Header("Content-Length", strconv.FormatInt(end-start, 10))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", name))
	c.Header("Content-type", http.DetectContentType(mime))
	c.Status(http.StatusPartialContent)
	file.Seek(start, io.SeekStart)
	io.CopyN(c.Writer, file, end-start)
	return nil
}
