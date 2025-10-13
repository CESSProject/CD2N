package handles

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CESSProject/CD2N/retriever/config"
	"github.com/CESSProject/CD2N/retriever/libs/client"
	"github.com/CESSProject/CD2N/retriever/libs/task"
	"github.com/CESSProject/CD2N/retriever/server/auth"
	"github.com/CESSProject/CD2N/retriever/server/response"
	"github.com/CESSProject/CD2N/retriever/utils"
	"github.com/CESSProject/go-sdk/chain"
	"github.com/CESSProject/go-sdk/libs/tsproto"
	"github.com/CESSProject/go-sdk/logger"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

const (
	DATA_PROCESS_TIMEOUT = 120 * time.Second
)

func (h *ServerHandle) LightningUpload(c *gin.Context) {
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "lightning upload error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "lightning upload error", "bad user info"))
		return
	}
	fid := c.PostForm("fid")
	if fid == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "lightning upload error", "bad file ID"))
		return
	}
	filename := c.PostForm("file_name")
	if filename == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "lightning upload error", "bad file name"))
		return
	}
	territory := c.PostForm("territory")
	if territory == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "lightning upload error", "invalid territory"))
	}
	hash, err := h.gateway.CreateFlashStorageOrder(user.Account, fid, filename, territory)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "lightning upload error", err.Error()))
		return
	}
	c.JSON(http.StatusOK, tsproto.NewResponse(response.CODE_UP_SUCCESS, "success", hash))
}

func (h *ServerHandle) UploadLocalFile(c *gin.Context) {
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "upload user file error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "upload user file error", "bad user info"))
		return
	}
	territory := c.PostForm("territory")
	if territory == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "upload user file error", "invalid territory"))
		return
	}
	fpath := c.PostForm("file_path")
	if fpath == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(response.CODE_UP_ERROR, "upload user file error", "invalid file path"))
		return
	}
	filename := c.PostForm("file_name")
	if filename == "" || len(filename) < 3 || len(filename) > 63 {
		c.JSON(http.StatusOK, tsproto.NewResponse(response.CODE_UP_INVALID_NAME, "upload user file error", "invalid file name"))
		return
	}
	async := c.PostForm("async") == "true"
	noProxy := c.PostForm("noProxy") == "true"
	encrypt := c.PostForm("encrypt") == "true"

	src, err := os.Open(fpath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(response.CODE_UP_ERROR, "upload user file error", err.Error()))
		return
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(c.Request.Context(), DATA_PROCESS_TIMEOUT)
	defer cancel()

	finfo, err := h.gateway.PreprocessFile(ctx, h.buffer, src, user.Account, territory, filename, encrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.upload(c, finfo, async, noProxy, false)
}

func (h *ServerHandle) UploadUserFileTemp(c *gin.Context) {
	acc := c.PostForm("account")
	pubkey, err := utils.ParsingPublickey(acc)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "upload user file error", err.Error()))
		return
	}
	territory := c.PostForm("territory")
	if territory == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "upload user file error", "bad file params"))
		return
	}
	async := c.PostForm("async") == "true"
	noProxy := c.PostForm("noProxy") == "true"
	encrypt := c.PostForm("encrypt") == "true"

	file, err := c.FormFile("file")

	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "upload user file error", err.Error()))
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(c.Request.Context(), DATA_PROCESS_TIMEOUT)
	defer cancel()
	finfo, err := h.gateway.PreprocessFile(ctx, h.buffer, src, pubkey, territory, file.Filename, encrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.upload(c, finfo, async, noProxy, false)
}

func (h *ServerHandle) UploadUserFile(c *gin.Context) {
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "upload user file error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "upload user file error", "bad user info"))
		return
	}
	territory := c.PostForm("territory")
	if territory == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "upload user file error", "bad file params"))
		return
	}
	async := c.PostForm("async") == "true"
	noProxy := c.PostForm("noProxy") == "true"
	encrypt := c.PostForm("encrypt") == "true"

	file, err := c.FormFile("file")

	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "upload user file error", err.Error()))
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	defer src.Close()

	ctx, cancel := context.WithTimeout(c.Request.Context(), DATA_PROCESS_TIMEOUT)
	defer cancel()
	finfo, err := h.gateway.PreprocessFile(ctx, h.buffer, src, user.Account, territory, file.Filename, encrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.upload(c, finfo, async, noProxy, false)
}

func (h *ServerHandle) upload(c *gin.Context, finfo task.FileInfo, async, noProxy, batchUpload bool) {
	//Precondition Check
	resp := h.CheckPreconditions(finfo.Fid, finfo.Territory, finfo.Owner, finfo.FileSize)
	if !async {
		if resp.Code != response.CODE_UP_SUCCESS {
			c.JSON(http.StatusBadRequest, resp)
			return
		}
		err := h.gateway.ProvideFile(context.Background(), h.buffer, h.partners, time.Hour, finfo, false)
		if err != nil {
			c.JSON(http.StatusInternalServerError, tsproto.NewResponse(response.CODE_UP_ERROR, "upload file error", err.Error()))
			return
		}
		h.gateway.BatchOffloadingWithFileInfo(finfo)
		if batchUpload {
			c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", BatchUploadResp{Fid: finfo.Fid}))
		} else {
			c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", finfo.Fid))
		}
		return
	}
	client.PutDataToRedis(
		h.partRecord, context.Background(),
		fmt.Sprintf("%s-async_upload-%s", h.nodeAddr, finfo.Fid),
		task.AsyncFinfoBox{Info: finfo, NonProxy: noProxy}, 0,
	)

	if resp.Code == response.CODE_UP_ERROR {
		c.JSON(http.StatusInternalServerError, resp)
		return
	} else if resp.Code != response.CODE_UP_SUCCESS || !noProxy {
		c.JSON(http.StatusOK, resp)
		return
	}
	if batchUpload {
		c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", BatchUploadResp{FileInfo: finfo}))
	} else {
		c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", finfo))
	}
}

func (h *ServerHandle) CheckPreconditions(fid, territory string, acc []byte, size int64) response.Response {
	cli, err := h.gateway.GetCessClient()
	if err != nil {
		return response.NewResp(response.CODE_UP_ERROR, err.Error(), fid)
	}
	//Check if the gateway is authorized
	osses, err := cli.QueryAuthList(acc, 0)
	if err != nil {
		return response.NewResp(response.CODE_UP_ERROR, err.Error(), fid)
	}
	if len(h.ossPubkey) <= 0 {
		key := cli.GetKeyInOrder()
		h.ossPubkey = key.PublicKey
		cli.PutKey(key.Address)
	}
	self, err := types.NewAccountID(h.ossPubkey)
	if err != nil {
		return response.NewResp(response.CODE_UP_ERROR, err.Error(), fid)
	}
	authed := false
	for _, oss := range osses {
		if self.Equal(&oss) {
			authed = true
		}
	}
	if !authed {
		return response.NewResp(response.CODE_UP_NOT_AUTH, "The user has not authorized the gateway", fid)
	}
	//Check if the territory space is valid
	tinfo, err := cli.QueryTerritory(acc, territory, 0)
	if err != nil {
		return response.NewResp(response.CODE_UP_ERROR, err.Error(), fid)
	}
	if tinfo.State != chain.TERRITORY_ACTIVE || tinfo.RemainingSpace.Int64() < size {
		return response.NewResp(response.CODE_UP_INSUFF_SPACE, "Insufficient territory space or not activated", fid)
	}

	fmeta, err := cli.QueryFileMetadata(fid, 0)
	if err == nil {
		for _, owner := range fmeta.Owner {
			if self.Equal(&owner.User) {
				return response.NewResp(response.CODE_UP_FILE_EXIST, "The user already owns the file", fid)
			}
		}
	}

	return response.NewResp(response.CODE_UP_SUCCESS, "success", fid)
}

func (h *ServerHandle) BatchUploadRequest(c *gin.Context) {
	var (
		info BatchFilesInfo
		err  error
	)

	if err := c.BindJSON(&info); err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "request batch upload error", err.Error()))
		return
	}
	if info.FileName == "" || info.Territory == "" || info.TotalSize <= 0 {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "request batch upload error", "bad request params"))
		return
	}
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "request batch upload error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "request batch upload error", "bad user info"))
		return
	}
	info.Owner = user.Account
	info.UpdateDate = time.Now()

	hash := hex.EncodeToString(utils.GetDataHash(info))
	info.Hash = hash
	info.FilePath, err = h.buffer.NewBufPath(hex.EncodeToString(user.Account), hash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "request batch upload error", err.Error()))
		return
	}
	if err = client.PutDataToRedis(h.partRecord, context.Background(),
		fmt.Sprintf("%s-batch_upload-%s", h.nodeAddr, hash), info, time.Hour*24); err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "request batch upload error", err.Error()))
		return
	}
	c.Header("hash", hash)
	c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", hash))
}

func (h *ServerHandle) BatchUpload(c *gin.Context) {
	dataRange := c.GetHeader("Range")
	hash := c.GetHeader("hash")
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "batch upload error", err.Error()))
		return
	}
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "batch upload error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "batch upload error", "bad user info"))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second*60)
	defer cancel()
	f, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "batch upload error", err.Error()))
		return
	}
	defer f.Close()
	res := h.batchUpload(ctx, hash, dataRange, user.Account, f)
	if res.Err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "batch upload error", res.Err.Error()))
		return
	}
	if res.UploadedSize < res.TotalSize {
		c.JSON(http.StatusPermanentRedirect, tsproto.NewResponse(http.StatusOK, "success", BatchUploadResp{ChunkEnd: res.UploadedSize}))
		return
	}
	cfile, err := os.Open(res.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "batch upload error", err.Error()))
		return
	}
	defer os.Remove(res.FilePath)
	defer cfile.Close()
	pctx, pcancel := context.WithTimeout(c.Request.Context(), DATA_PROCESS_TIMEOUT)
	defer pcancel()
	finfo, err := h.gateway.PreprocessFile(pctx, h.buffer, cfile, user.Account, res.Territory, res.FileName, res.Encrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "batch upload error", err.Error()))
		return
	}
	h.upload(c, finfo, res.AsyncUpload, res.NoTxProxy, true)
}

func (h *ServerHandle) batchUpload(ctx context.Context, hash, dataRange string, acc []byte, reader io.Reader) BatchUploadResult {
	var info BatchFilesInfo
	if err := client.GetDataFromRedis(h.partRecord, context.Background(), fmt.Sprintf("%s-batch_upload-%s", h.nodeAddr, hash), &info); err != nil {
		return BatchUploadResult{Err: err}
	}
	start, end, err := utils.ParseFileRange(dataRange)
	if err != nil {
		return BatchUploadResult{Err: err}
	}
	resCh := make(chan BatchUploadResult, 1)
	h.batchUploadQueue <- BatchUploadCmd{
		Hash:   hash,
		User:   acc,
		Reader: reader,
		Start:  start,
		End:    end,
		Ctx:    ctx,
		Res:    resCh,
	}
	select {
	case res := <-resCh:
		return res
	case <-ctx.Done():
		return BatchUploadResult{Err: errors.New("timeout")}
	}
}

func (h *ServerHandle) batchUploadServer() {
	for cmd := range h.batchUploadQueue {
		if cmd.Reader == nil || cmd.Res == nil || cmd.Ctx == nil {
			cmd.Res <- BatchUploadResult{Err: errors.New("invalid params")}
			continue
		}
		batchCmd := cmd
		h.pool.Submit(func() {
			if _, ok := h.filepartMap.LoadOrStore(batchCmd.Hash, struct{}{}); ok {
				h.batchUploadQueue <- batchCmd
				return
			}
			defer h.filepartMap.Delete(batchCmd.Hash)
			var (
				f    *os.File
				info BatchFilesInfo
				err  error
			)
			key := fmt.Sprintf("%s-batch_upload-%s", h.nodeAddr, batchCmd.Hash)
			if err := client.GetDataFromRedis(h.partRecord, batchCmd.Ctx, key, &info); err != nil {
				batchCmd.Res <- BatchUploadResult{Err: err}
				return
			}

			if info.UploadedSize < batchCmd.Start {
				h.batchUploadQueue <- batchCmd
				return
			}
			switch {
			case time.Since(info.UpdateDate) >= time.Hour*24:
				os.Remove(info.FilePath)
				client.DeleteMessage(h.partRecord, batchCmd.Ctx, key)
				batchCmd.Res <- BatchUploadResult{Err: errors.New("the data has expired.")}
				return
			case info.UploadedSize == info.TotalSize:
				client.DeleteMessage(h.partRecord, batchCmd.Ctx, key)
				batchCmd.Res <- BatchUploadResult{BatchFilesInfo: info}
				return
			case (batchCmd.Start == 0 && batchCmd.End == 0) || (batchCmd.End != 0 && batchCmd.End <= batchCmd.Start):
				batchCmd.Res <- BatchUploadResult{Err: errors.New("bad data range")}
				return
			case info.Owner == nil || !bytes.Equal(batchCmd.User, info.Owner):
				batchCmd.Res <- BatchUploadResult{Err: errors.New("unauthorized access")}
				return
			case batchCmd.End == 0:
				batchCmd.End = info.TotalSize
			}

			buf := make([]byte, batchCmd.End-batchCmd.Start)
			if n, err := batchCmd.Reader.Read(buf); err != nil {
				batchCmd.Res <- BatchUploadResult{Err: err}
				return
			} else if n != int(batchCmd.End-batchCmd.Start) {
				batchCmd.Res <- BatchUploadResult{Err: errors.New("bad data")}
				return
			}

			if _, err = os.Stat(info.FilePath); err != nil {
				if f, err = os.Create(info.FilePath); err != nil {
					batchCmd.Res <- BatchUploadResult{Err: err}
					return
				}
			} else if f, err = os.OpenFile(info.FilePath, os.O_WRONLY, 0644); err != nil {
				batchCmd.Res <- BatchUploadResult{Err: err}
				return
			}
			defer f.Close()
			if _, err := f.WriteAt(buf, batchCmd.Start); err != nil {
				batchCmd.Res <- BatchUploadResult{Err: err}
				return
			}
			info.UploadedSize += batchCmd.End - batchCmd.Start
			info.UpdateDate = time.Now()
			if batchCmd.End == info.TotalSize {
				client.DeleteMessage(h.partRecord, batchCmd.Ctx, key)
			} else if err = client.PutDataToRedis(h.partRecord, batchCmd.Ctx,
				fmt.Sprintf("%s-batch_upload-%s", h.nodeAddr, batchCmd.Hash), info, time.Hour*24); err != nil {
				batchCmd.Res <- BatchUploadResult{Err: err}
				return
			}
			batchCmd.Res <- BatchUploadResult{BatchFilesInfo: info}
		})
	}
}

func (h *ServerHandle) AsyncUploadFiles(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute * 15)
	for {
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}

		keys, err := client.GetKeysByPrefix(h.partRecord, fmt.Sprintf("%s-async_upload-", h.nodeAddr))
		if err != nil {
			logger.GetLogger(config.LOG_GATEWAY).Error("query async upload task error ", err)
			continue
		}

		for _, k := range keys {
			key := k
			h.pool.Submit(func() {
				if err := func(key string) error {
					if !strings.Contains(key, config.DB_FINFO_PREFIX) {
						return nil
					}
					var box task.AsyncFinfoBox
					if err := client.GetDataFromRedis(h.partRecord, ctx, key, &box); err != nil {
						logger.GetLogger(config.LOG_GATEWAY).Info("get file info box from db error ", err)
						return nil
					}

					if box.NonProxy {
						cli, err := h.gateway.GetCessClient()
						if err != nil {
							logger.GetLogger(config.LOG_GATEWAY).Error("provide file async error ", err)
							return nil
						}
						_, err = cli.QueryDealMap(box.Info.Fid, 0)
						if err != nil {
							logger.GetLogger(config.LOG_GATEWAY).Error("provide file async error ", err)
							return nil
						}
						if err := h.gateway.ProvideFile(context.Background(), h.buffer, h.partners, time.Hour, box.Info, true); err != nil {
							logger.GetLogger(config.LOG_GATEWAY).Error("provide file async error ", err)
							return nil
						}
						client.DeleteMessage(h.partRecord, ctx, key)
						return nil
					}

					if err := h.gateway.ProvideFile(context.Background(), h.buffer, h.partners, time.Hour, box.Info, false); err != nil {
						logger.GetLogger(config.LOG_GATEWAY).Error("provide file async error ", err)
					} else {
						h.gateway.BatchOffloadingWithFileInfo(box.Info)
					}
					client.DeleteMessage(h.partRecord, ctx, key)
					return nil
				}(key); err != nil {
					logger.GetLogger(config.LOG_GATEWAY).Error("async upload files error ", err)
				}
			})

		}
	}
}
