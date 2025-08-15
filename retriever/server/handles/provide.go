package handles

import (
	"context"
	"net/http"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
)

func (h *ServerHandle) ClaimOffloadingData(c *gin.Context) {
	var req tsproto.FileRequest
	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "claim file error", "bad request params"))
		return
	}

	du, err := h.gateway.ClaimOffloadingData(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "claim file error", err.Error()))
		return
	}

	err = h.partners.SaveOrUpdateCacher(req.Pubkey, c.ClientIP(), req.StorageNodes)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "claim file error", err.Error()))
		return
	}
	c.Header("Did", du.Did)
	c.File(du.Path)
}

func (h *ServerHandle) ClaimFile(c *gin.Context) {
	var req tsproto.FileRequest
	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "claim file error", "bad request params"))
		return
	}

	key, err := crypto.DecompressPubkey(req.Pubkey)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "claim file error", err.Error()))
		return
	}
	addr := crypto.PubkeyToAddress(*key).Hex()
	err = h.partners.SaveOrUpdateCacher(req.Pubkey, c.ClientIP(), req.StorageNodes)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "claim file error", err.Error()))
		return
	}
	resp, err := h.gateway.ClaimFile(context.Background(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "claim file error", err.Error()))
		return
	}
	h.partners.UpdateCacherToken(resp.Token, addr)
	logger.GetLogger(config.LOG_PROVIDER).Infof("L2 Node %s claim fragments from file %s  success.", resp.Token, resp.Fid)
	c.JSON(http.StatusOK, tsproto.NewResponse(http.StatusOK, "success", resp))
}

func (h *ServerHandle) FetchFile(c *gin.Context) {
	fid := c.Query("fid")
	fragment := c.Query("fragment")
	token := c.Request.Header.Get("token")
	if fid == "" || fragment == "" || token == "" {
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "fetch file error", "bad request params"))
		return
	}
	addr, _ := h.partners.GetCacherAddr(token)
	fpath, err := h.gateway.FetchFile(context.Background(), fid, fragment, token)
	if err != nil {
		h.partners.CacherDistribution(addr, false)
		c.JSON(http.StatusBadRequest, tsproto.NewResponse(http.StatusBadRequest, "fetch file error", err.Error()))
		return
	}
	h.partners.CacherDistribution(addr, true)
	logger.GetLogger(config.LOG_PROVIDER).Infof("L2 Node %s fetch fragment %s from file %s  success.", token, fragment, fid)
	c.File(fpath)
}
