package server

import (
	"errors"
	"net/http"
	"net/http/pprof"
	"strings"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/server/auth"
	"github.com/CD2N/CD2N/retriever/server/handles"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/gin-gonic/gin"
)

func NewRouter() *gin.Engine {
	router := gin.New()
	router.Use(Cors())
	router.Use(TrimGetSuffix())
	router.Use(gin.CustomRecovery(func(c *gin.Context, err any) {
		errResp := tsproto.NewResponse(http.StatusInternalServerError, "internal server error", err)
		c.JSON(http.StatusInternalServerError, errResp)
		c.Abort()
	}))
	//registerActivityRouter(router)
	return router
}

func TrimGetSuffix() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet {
			req := c.Request.RequestURI
			idx := strings.LastIndex(req, "&")
			if idx > 0 {
				c.Request.RequestURI = req[0:idx]
			}
		}
		c.Next()
	}
}

func HealthCheck(c *gin.Context) {
	c.JSON(200, 0)
}

func DebugHandle(c *gin.Context) {
	c.JSON(200, "ok")
}

func TokenVerify(c *gin.Context) {
	if strings.Contains(c.Request.RequestURI, "/gentoken") ||
		strings.Contains(c.Request.RequestURI, "/download") ||
		strings.Contains(c.Request.RequestURI, "/capsule") ||
		strings.Contains(c.Request.RequestURI, "/reencrypt") {
		c.Next()
		return
	}
	clams, err := parseToken(c)
	if err != nil {
		resp := tsproto.NewResponse(http.StatusForbidden, "Invalid token", err.Error())
		c.JSON(resp.Code, resp)
		c.Abort()
		return
	}
	c.Set("user", clams.User)
	c.Next()
}

func parseToken(c *gin.Context) (*auth.CustomClaims, error) {
	token := strings.TrimPrefix(c.GetHeader("token"), "Bearer ")
	if token == "" {
		return nil, errors.New("invalid token")
	}

	clams, err := auth.Jwth().ParseToken(token)
	if err != nil {
		return nil, err
	}
	return clams, nil
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type,AccessToken,X-CSRF-Token, Authorization, Token, token")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PATCH, PUT")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")

		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
	}
}

func RegisterMonitor(router *gin.Engine, apikey string) {
	debugGroup := router.Group("/debug/pprof")
	debugGroup.GET("/", gin.WrapH(http.HandlerFunc(pprof.Index)))
	debugGroup.GET("/heap", gin.WrapH(pprof.Handler("heap")))
	debugGroup.GET("/goroutine", gin.WrapH(pprof.Handler("goroutine")))
	debugGroup.GET("/allocs", gin.WrapH(pprof.Handler("allocs")))
	debugGroup.GET("/block", gin.WrapH(pprof.Handler("block")))
	debugGroup.GET("/mutex", gin.WrapH(pprof.Handler("mutex")))
	debugGroup.GET("/threadcreate", gin.WrapH(pprof.Handler("threadcreate")))
	debugGroup.GET("/profile", gin.WrapH(http.HandlerFunc(pprof.Profile)))
	debugGroup.POST("/symbol", gin.WrapH(http.HandlerFunc(pprof.Symbol)))
	debugGroup.GET("/trace", gin.WrapH(http.HandlerFunc(pprof.Trace)))
	debugGroup.GET("/cmdline", gin.WrapH(http.HandlerFunc(pprof.Cmdline)))
}

func RegisterHandles(router *gin.Engine, h *handles.ServerHandle) {
	router.Use(h.AddNodeAddressHeader)
	router.GET("/status", h.GetNodeInfo)
	router.POST("/upfile", h.UploadUserFileTemp)
	router.GET("/capacity/:addr", h.QueryCacheCap)
	router.GET("/querydata/:did", h.QueryData)

	router.POST("/cache-fetch", h.Ac.RetrievalLimitMiddleware(), h.FetchCacheData)
	router.POST("/provide", h.Ac.ProvideDataLimitMiddleware(), h.ProvideData)
	conf := config.GetConfig()
	if !conf.LaunchGateway {
		return
	}
	router.POST("/claim", h.Ac.ClaimDataLimitMiddleware(), h.ClaimFile)
	router.GET("/fetch", h.FetchFile)
	router.POST("/offload", h.Ac.ClaimDataLimitMiddleware(), h.ClaimOffloadingData)

	gateway := router.Group("/gateway")
	gateway.Use(TokenVerify)
	gateway.GET("/capsule/:fid", h.GetPreCapsule)
	gateway.POST("/reencrypt", h.ReEncryptKey)
	gateway.POST("/gentoken", h.GenToken)
	gateway.HEAD("/download/:fid/:segment", h.DownloadUserFile)
	gateway.GET("/download/:fid", h.DownloadUserFile)
	gateway.GET("/download/:fid/:segment", h.DownloadUserFile)
	gateway.POST("/upload/file", h.UploadUserFile)
	gateway.POST("/part-upload", h.RequestPartsUpload)
	gateway.POST("/upload/part", h.UploadFileParts)

	if !conf.DisableLocalSvc {
		gateway.POST("/upload/local", h.UploadLocalFile)
		gateway.POST("/upload/light", h.LightningUpload)
	}
}
