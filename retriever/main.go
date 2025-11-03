package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/CESSProject/CD2N/retriever/config"
	"github.com/CESSProject/CD2N/retriever/server"
	"github.com/CESSProject/go-sdk/logger"
)

const VERSION = "v0.2.0"

func main() {
	var confPath string
	if len(os.Args) >= 2 {
		confPath = os.Args[1]
	}
	log.Println("CODE VERSION:", VERSION)
	err := config.InitDefaultConfig(confPath)
	if err != nil {
		log.Fatal(err)
	}

	logger := logger.InitGlobalLogger()

	logDir := filepath.Join(config.GetConfig().WorkSpace, "logs")
	if err = os.MkdirAll(logDir, 0755); err != nil {
		log.Fatal(err)
	}
	if _, err := logger.RegisterLogger(config.LOG_PROVIDER, filepath.Join(logDir, "provide.log"), "json"); err != nil {
		log.Fatal("register logger error", err)
	}
	if _, err := logger.RegisterLogger(config.LOG_GATEWAY, filepath.Join(logDir, "gateway.log"), "json"); err != nil {
		log.Fatal("register logger error", err)
	}
	if _, err := logger.RegisterLogger(config.LOG_RETRIEVE, filepath.Join(logDir, "retrieve.log"), "json"); err != nil {
		log.Fatal("register logger error", err)
	}
	server.SetupGin()
}
