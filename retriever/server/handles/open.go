package handles

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	"github.com/CESSProject/CD2N/retriever/config"
	"github.com/CESSProject/CD2N/retriever/utils"
	"github.com/CESSProject/go-sdk/libs/tsproto"
	"github.com/CESSProject/go-sdk/logger"
	"github.com/gin-gonic/gin"
)

func (h *ServerHandle) OpenUserFile(c *gin.Context) {
    fid := c.Param("fid")
    if fid == "" {
        c.JSON(http.StatusBadRequest,
            tsproto.NewResponse(http.StatusBadRequest, "open file error", "missing file id"))
        return
    }

    key := fid 
    
    err := h.gateway.WaitFileCache(key, time.Minute)
    if err != nil {
        c.JSON(http.StatusGatewayTimeout,
            tsproto.NewResponse(http.StatusGatewayTimeout, "open file error", "cache timeout or file unavailable"))
        return
    }
    defer h.gateway.ReleaseCacheTask(key)

    fileRange := c.Request.Header.Get("Range")
    capsule := c.GetHeader("Capsule")
    rkb := c.GetHeader("Rkb")
    pkX := c.GetHeader("Pkx")

    info, err := h.gateway.RetrieveDataFromCache(fid, key, "", fileRange)
    if err != nil {
        info, err = h.gateway.DownloadData(
            context.Background(),
            h.buffer,
            h.retr,
            fid,
            "",
            fileRange,
        )
        if err != nil {
            logger.GetLogger(config.LOG_GATEWAY).Errorf("failed to download file %s: %v", fid, err)
            c.JSON(http.StatusInternalServerError,
                tsproto.NewResponse(http.StatusInternalServerError, "open file error", "failed to retrieve data from network"))
            return
        }
    }

    if rkb != "" && pkX != "" {
        uniqueHash := utils.CalcSha256Hash([]byte(info.Fid), []byte(info.Path), []byte(time.Now().String()))
        dpath, err := h.buffer.NewBufPath(hex.EncodeToString(uniqueHash))
        if err != nil {
            c.JSON(http.StatusInternalServerError,
                tsproto.NewResponse(http.StatusInternalServerError, "open file error", "system buffer error"))
            return
        }
        
        defer func() {
            if _, err := os.Stat(dpath); err == nil {
                os.Remove(dpath)
            }
        }()

        pubkeyX, err := utils.ParsingPublickey(pkX)
        if err != nil {
            c.JSON(http.StatusBadRequest,
                tsproto.NewResponse(http.StatusBadRequest, "open file error", "invalid public key"))
            return
        }

        if err := h.gateway.DecryptData(&info, []byte(capsule), []byte(rkb), pubkeyX, dpath); err != nil {
            c.JSON(http.StatusInternalServerError,
                tsproto.NewResponse(http.StatusInternalServerError, "open file error", "decryption failed"))
            return
        }
    }

    if err := ServeStream(c, info); err != nil {
        if !c.Writer.Written() {
            c.JSON(http.StatusInternalServerError,
                tsproto.NewResponse(http.StatusInternalServerError, "streaming error", err.Error()))
        }
        return
    }
}