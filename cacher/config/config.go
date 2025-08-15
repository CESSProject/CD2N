package config

import (
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	LOG_NODE  = "node"
	LOG_TASK  = "task"
	LOG_CHAIN = "chain"
)

type Config struct {
	WorkSpace       string   `json:"workspace"`
	Endpoint        string   `json:"endpoint"`
	Expiration      int64    `json:"expiration"`
	CacheSize       int64    `json:"cache_size"`
	ChainId         int64    `json:"chain_id"`
	Rpcs            []string `json:"rpcs"`
	SecretKey       string   `json:"secret_key"`
	Token           string   `json:"token"`
	TokenAcc        string   `json:"token_acc"`
	TokenAccSign    string   `json:"tokenacc_sign"`
	ProtoContract   string   `json:"proto_contract"`
	Staking         string   `json:"staking"`
	MinerConfigPath string   `json:"miner_config_path"`
	Retrievers      []Node   `json:"retrievers"`
	StorageNodes    []Node   `json:"storage_nodes"`
	GasFreeCap      int64
	GasLimit        uint64
	Network         uint16
}

type Node struct {
	Account  string `json:"account"`
	Endpoint string `json:"endpoint"`
}

type MinerConfig struct {
	Miners []Miner `json:"miners"`
}

type Miner struct {
	Mnemonic string `json:"mnemonic" `
	Port     int    `json:"port"`
}

const (
	DEFAULT_PATH         = "./config.yaml"
	DEFAULT_MINER_CONFIG = "/opt/cess/mineradm/config.yaml"
	DEFAULT_CACHE_DIR    = "cache"
	DEFAULT_BUFFER_DIR   = "buffer"
	DEFAULT_LOG_DIR      = "logs"
	DEFAULT_DB_DIR       = "file_records"
)

var conf *Config

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DEFAULT_PATH
	}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	err := v.ReadInConfig()
	if err != nil {
		return nil, errors.Wrap(err, "load config file error")
	}
	config := &Config{}
	err = v.Unmarshal(config)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal config data error")
	}
	return config, nil
}

func LoadGeneralConfig(path string, conf any) error {
	if path == "" {
		path = DEFAULT_PATH
	}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	err := v.ReadInConfig()
	if err != nil {
		return errors.Wrap(err, "load config file error")
	}
	err = v.Unmarshal(conf)
	if err != nil {
		return errors.Wrap(err, "unmarshal config data error")
	}
	return nil
}

func InitDefaultConfig(path string) error {
	var err error
	conf, err = LoadConfig(path)
	if err != nil {
		return errors.Wrap(err, "init default config error")
	}
	if conf.WorkSpace == "" {
		conf.WorkSpace = "./"
	}
	if conf.MinerConfigPath == "" {
		conf.MinerConfigPath = DEFAULT_MINER_CONFIG
	}
	if conf.CacheSize == 0 {
		conf.CacheSize = 16 * 1024 * 1024 * 1024 //16GiB
	}
	if conf.Expiration == 0 {
		conf.Expiration = int64(time.Hour * 48)
	}
	if conf.Token != "" && conf.TokenAcc != "" &&
		conf.TokenAccSign != "" && conf.SecretKey == "" {
		return errors.Wrap(errors.New("secret key is empty"), "init default config error")
	}
	if conf.Network == 0 {
		conf.Network = utils.TESTNET_FORMAT
	}
	if conf.SecretKey != "" {
		return nil
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return errors.Wrap(err, "init default config error")
	}
	conf.SecretKey = hex.EncodeToString(key.D.Bytes())
	log.Println(conf.SecretKey)
	return nil
}

func GetConfig() Config {
	return *conf
}

func BuildWorkSpace() error {
	if _, err := os.Stat(conf.WorkSpace); err != nil {
		err = os.MkdirAll(conf.WorkSpace, 0755)
		if err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}
	//init cache dir
	cacheDir := filepath.Join(conf.WorkSpace, DEFAULT_CACHE_DIR)
	if _, err := os.Stat(cacheDir); err != nil {
		err = os.Mkdir(cacheDir, 0755)
		if err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}
	bufferDir := filepath.Join(conf.WorkSpace, DEFAULT_BUFFER_DIR)
	if _, err := os.Stat(bufferDir); err != nil {
		err = os.Mkdir(bufferDir, 0755)
		if err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}
	logDir := filepath.Join(conf.WorkSpace, DEFAULT_LOG_DIR)
	if _, err := os.Stat(logDir); err != nil {
		err = os.Mkdir(logDir, 0755)
		if err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}
	logger := logger.InitGlobalLogger()
	if _, err := logger.RegisterLogger(LOG_NODE, filepath.Join(logDir, "node.log"), "json"); err != nil {
		log.Fatal("register logger error", err)
	}
	if _, err := logger.RegisterLogger(LOG_TASK, filepath.Join(logDir, "task.log"), "json"); err != nil {
		log.Fatal("register logger error", err)
	}
	if _, err := logger.RegisterLogger(LOG_CHAIN, filepath.Join(logDir, "chain.log"), "json"); err != nil {
		log.Fatal("register logger error", err)
	}
	return nil
}
