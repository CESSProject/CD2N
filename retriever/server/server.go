package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/server/auth"
	"github.com/CD2N/CD2N/retriever/server/handles"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/gin-gonic/gin"
)

const (
	READ_TIMEOUT  = 300
	WRITE_TIMEOUT = 300
)

const (
	INTERNAL_ERR_MSG = "Internal error"
	BADREQ_ERR_MSG   = "Bad reequest"
	SUCCESS_MSG      = "success"
)

func SetupGin() {

	k, err := utils.GetRandomBytes()
	if err != nil {
		log.Fatal(err)
	}
	auth.SetupAuth(base64.StdEncoding.EncodeToString(k), int64(time.Hour*72))
	conf := config.GetConfig()
	gin.SetMode(gin.ReleaseMode)
	log.Println("start init retriever web handles ...")
	handle := handles.NewServerHandle()
	err = handle.InitHandlesRuntime(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	log.Println("init retriever web handles success.")

	router := NewRouter()
	RegisterHandles(router, handle)
	//RegisterMonitor(router, "retriever-monitor-2025")

	httpServer := &http.Server{
		Addr:           fmt.Sprintf(":%d", conf.SvcPort),
		Handler:        router,
		ReadTimeout:    time.Second * READ_TIMEOUT,
		WriteTimeout:   time.Second * WRITE_TIMEOUT,
		MaxHeaderBytes: 1 << 20,
	}
	log.Println("CD2N server start!")
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %s\n", err)
	}
}
