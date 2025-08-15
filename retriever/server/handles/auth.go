package handles

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CD2N/CD2N/retriever/server/auth"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

const (
	ACCPREFIX_CESS_MAINNET = "ce"
	ACCPREFIX_CESS_TESTNET = "cX"
	ACCPREFIX_ETHEREUM     = "0x"
)

func (h *ServerHandle) GenToken(c *gin.Context) {
	acc := c.PostForm("account")
	msg := c.PostForm("message")
	sign := c.PostForm("sign")
	if acc == "" || msg == "" || sign == "" {
		resp := tsproto.NewResponse(http.StatusBadRequest, "login error", "bad request params")
		c.JSON(resp.Code, resp)
		return
	}
	//check message
	unix, err := strconv.ParseInt(msg, 10, 64)
	if err != nil {
		resp := tsproto.NewResponse(http.StatusInternalServerError, "login error", "The timestamp format is incorrect")
		c.JSON(resp.Code, resp)
		return
	}
	if time.Duration(time.Now().Unix()-unix) > time.Minute {
		resp := tsproto.NewResponse(http.StatusBadRequest, "login error", "invalid timestamp")
		c.JSON(resp.Code, resp)
		return
	}
	account, err := ParsingAndVerifyPublickey(acc, msg, sign)
	if err != nil {
		resp := tsproto.NewResponse(http.StatusBadRequest, "login error", err.Error())
		c.JSON(resp.Code, resp)
		return
	}
	token, err := auth.Jwth().GenerateToken(auth.UserInfo{Account: account})
	if err != nil {
		resp := tsproto.NewResponse(http.StatusInternalServerError, "login error", err.Error())
		c.JSON(resp.Code, resp)
		return
	}
	resp := tsproto.NewResponse(http.StatusOK, "success", token)
	c.JSON(resp.Code, resp)

}

func ParsingAndVerifyPublickey(acc, message, sign string) ([]byte, error) {
	sign = strings.TrimPrefix(sign, "0x")
	signBytes, err := hex.DecodeString(sign)
	if err != nil {
		return nil, errors.Wrap(err, "parsing and verifying account error")
	}
	hd := sha256.Sum256([]byte(message))
	msg := append([]byte("<Bytes>"), append(hd[:], []byte("</Bytes>")...)...)

	if strings.HasPrefix(acc, ACCPREFIX_CESS_MAINNET) || strings.HasPrefix(acc, ACCPREFIX_CESS_TESTNET) {
		pubkey, err := utils.ParsingPublickey(acc)
		if err != nil {
			return nil, errors.Wrap(err, "parsing and verifying account error")
		}
		ok, err := utils.VerifySR25519WithPublickey(msg[:], signBytes, pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "parsing and verifying account error")
		}
		if !ok {
			return nil, errors.Wrap(errors.New("verify sign error"), "parsing and verifying account error")
		}
		return pubkey, nil
	}
	if strings.HasPrefix(acc, ACCPREFIX_ETHEREUM) {
		pubkey, err := crypto.SigToPub(msg[:], signBytes)
		if err != nil {
			return nil, errors.Wrap(err, "parsing and verifying account error")
		}
		parsedAcc := crypto.PubkeyToAddress(*pubkey).Hex()

		if strings.EqualFold(parsedAcc, acc) {
			return nil, errors.Wrap(errors.New("verify sign error"), "parsing and verifying account error")
		}
		return ConvertPubkey(parsedAcc), nil
	}
	return nil, errors.Wrap(errors.New("bad account"), "parsing and verifying account error")
}
