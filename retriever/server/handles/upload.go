package handles

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CD2N/CD2N/retriever/server/auth"
	"github.com/CD2N/CD2N/retriever/server/response"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
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

	finfo, err := h.gateway.PreprocessFile(h.buffer, src, user.Account, territory, filename, encrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.upload(c, finfo, async, noProxy)
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

	finfo, err := h.gateway.PreprocessFile(h.buffer, src, pubkey, territory, file.Filename, encrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.upload(c, finfo, async, noProxy)
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

	finfo, err := h.gateway.PreprocessFile(h.buffer, src, user.Account, territory, file.Filename, encrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.upload(c, finfo, async, noProxy)
}

func (h *ServerHandle) upload(c *gin.Context, finfo task.FileInfo, async, noProxy bool) {
	//Precondition Check
	resp := h.CheckPreconditions(finfo.Fid, finfo.Territory, finfo.Owner, finfo.FileSize)
	if !async {
		if resp.Code != response.CODE_UP_SUCCESS {
			c.JSON(http.StatusBadRequest, resp)
			return
		}
		err := h.gateway.ProvideFile(context.Background(), h.buffer, time.Hour, finfo, false)
		if err != nil {
			c.JSON(http.StatusInternalServerError, tsproto.NewResponse(response.CODE_UP_ERROR, "upload file error", err.Error()))
			return
		}
		h.gateway.BatchOffloadingWithFileInfo(finfo)
		c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", finfo.Fid))
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
	c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", finfo))
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

func (h *ServerHandle) UploadFileParts(c *gin.Context) {
	partId := c.PostForm("partid")
	shadowHash := c.PostForm("shadowhash")
	async := c.PostForm("async") == "true"
	noProxy := c.PostForm("noProxy") == "true"
	encrypt := c.PostForm("encrypt") == "true"

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	if partId == "" || shadowHash == "" {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", "bad params"))
		return
	}
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "parts upload error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "parts upload error", "bad user info"))
		return
	}
	idx, err := strconv.Atoi(partId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	fkey := hex.EncodeToString(utils.CalcSha256Hash(user.Account, []byte(shadowHash), []byte(partId)))
	fpath, err := h.buffer.NewBufPath(hex.EncodeToString(user.Account), shadowHash, fkey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	err = h.SaveFileToBuf(file, fpath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	h.buffer.AddData(fkey, fpath)
	v, ok := h.filepartMap.Load(shadowHash)
	if !ok {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", "no parts record"))
		return
	}
	lock, ok := v.(*sync.Mutex)
	if !ok {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", "parse key locker error"))
		return
	}
	lock.Lock()
	defer lock.Unlock()
	var partsInfo PartsInfo
	err = client.GetDataFromRedis(h.partRecord, context.Background(), fmt.Sprintf("%s-filepart-%s", h.nodeAddr, shadowHash), &partsInfo)
	if err != nil {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	if idx >= len(partsInfo.Parts) || idx < 0 {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "parts upload error", "bad file index"))
		return
	}
	if !bytes.Equal(partsInfo.Owner, user.Account) {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "parts upload error", "file owner mismatch"))
		return
	}
	partsInfo.Parts[idx] = file.Filename
	partsInfo.PartsCount++
	if partsInfo.PartsCount < partsInfo.TotalParts {
		if err = client.PutDataToRedis(h.partRecord, context.Background(),
			fmt.Sprintf("%s-filepart-%s", h.nodeAddr, shadowHash), partsInfo, 0); err != nil {
			h.buffer.RemoveData(fpath)
			c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
			return
		}
		c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", partId))
		return
	}
	//combine files
	defer client.DeleteMessage(h.partRecord, context.Background(), fmt.Sprintf("%s-filepart-%s", h.nodeAddr, shadowHash))
	cfile, err := h.CombineFileParts(partsInfo)
	if err != nil {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "parts upload error", err.Error()))
		return
	}
	f, err := os.Open(cfile)
	if err != nil {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	fname := partsInfo.FileName
	if partsInfo.Archive != "" && partsInfo.DirName != "" {
		fname = partsInfo.DirName
	}
	defer f.Close()

	finfo, err := h.gateway.PreprocessFile(h.buffer, f, user.Account, partsInfo.Territory, fname, encrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.upload(c, finfo, async, noProxy)
}

func (h *ServerHandle) RequestPartsUpload(c *gin.Context) {
	var (
		partsInfo PartsInfo
		err       error
	)

	if err := c.BindJSON(&partsInfo); err != nil {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "request parts upload error", err.Error()))
		return
	}
	if partsInfo.FileName == "" || partsInfo.ShadowHash == "" || partsInfo.Territory == "" ||
		partsInfo.TotalParts <= 0 || partsInfo.TotalSize <= 0 {
		c.JSON(http.StatusInternalServerError, tsproto.NewResponse(http.StatusInternalServerError, "request parts upload error", "bad request params"))
		return
	}
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "request parts upload error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "request parts upload error", "bad user info"))
		return
	}
	if _, ok := h.filepartMap.LoadOrStore(partsInfo.ShadowHash, &sync.Mutex{}); ok {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "request parts upload error", "file part is uploading"))
		return
	}
	partsInfo.Owner = user.Account
	partsInfo.UpdateDate = time.Now()
	partsInfo.Parts = make([]string, partsInfo.TotalParts)

	if err = client.PutDataToRedis(h.partRecord, context.Background(),
		fmt.Sprintf("%s-filepart-%s", h.nodeAddr, partsInfo.ShadowHash), partsInfo, 0); err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "upload user file error", err.Error()))
		return
	}
	c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", nil))
}

func (h *ServerHandle) CombineFileParts(info PartsInfo) (string, error) {
	var files []string = make([]string, 0, info.TotalParts)

	tmpName := hex.EncodeToString(utils.CalcSha256Hash(info.Owner, []byte(info.Territory+info.DirName)))
	fpath, err := h.buffer.NewBufPath(tmpName)
	if err != nil {
		return "", errors.Wrap(err, "combine file parts error")
	}

	for idx := 0; idx < info.TotalParts; idx++ {
		fkey := hex.EncodeToString(utils.CalcSha256Hash(info.Owner, []byte(info.ShadowHash), []byte(fmt.Sprint(idx))))
		subPath, err := h.buffer.NewBufPath(hex.EncodeToString(info.Owner), info.ShadowHash, fkey)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}
		files = append(files, subPath)
	}
	defer func() {
		for _, f := range files {
			h.buffer.RemoveData(f)
		}
	}()
	if info.Archive != "" && info.DirName != "" {
		ar, err := utils.NewArchiver(info.Archive)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}

		err = ar.Archive(files, fpath)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}
		h.buffer.AddData(tmpName, fpath)
		return fpath, nil
	}
	file, err := os.Create(fpath)
	if err != nil {
		return "", errors.Wrap(err, "combine file parts error")
	}
	defer file.Close()
	for _, subfile := range files {
		data, err := os.ReadFile(subfile)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}
		_, err = file.Write(data)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}
	}
	h.buffer.AddData(tmpName, fpath)
	return fpath, nil
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

		for _, key := range keys {
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
					if err := h.gateway.ProvideFile(context.Background(), h.buffer, time.Hour, box.Info, true); err != nil {
						logger.GetLogger(config.LOG_GATEWAY).Error("provide file async error ", err)
						return nil
					}
					client.DeleteMessage(h.partRecord, ctx, key)
					return nil
				}

				if err := h.gateway.ProvideFile(context.Background(), h.buffer, time.Hour, box.Info, false); err != nil {
					logger.GetLogger(config.LOG_GATEWAY).Error("provide file async error ", err)
				} else {
					h.gateway.BatchOffloadingWithFileInfo(box.Info)
				}
				client.DeleteMessage(h.partRecord, ctx, key)
				return nil
			}(key); err != nil {
				logger.GetLogger(config.LOG_GATEWAY).Error("async upload files error ", err)
			}
		}
	}
}
