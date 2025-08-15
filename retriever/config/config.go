package config

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type Config struct {
	DiskConfig
	ChainConfig
	NodeConfig
	ServerConfig
}

type DiskConfig struct {
	FileBufferSize   int64
	GatewayCacheSize int64
	WorkSpace        string
}

type ChainConfig struct {
	ChainId       int64
	Rpcs          []string
	ProtoContract string
	GasFreeCap    int64
	GasLimit      uint64
	RechargeSize  uint64
	GasDeposit    string
}

type NodeConfig struct {
	SecretKey    string
	Token        string
	TokenAcc     string
	TokenAccSign string
	Mnemonic     string
}

type ServerConfig struct {
	PoolName        string
	DisableLocalSvc bool // Whether to disable local service
	LaunchGateway   bool
	Debug           bool
	RedisAddress    string //redis host:port
	RedisLoacl      string
	TeeAddress      string
	Endpoint        string
	IpfsHost        string
	RedisPwd        string
	SvcPort         int
}

const (
	KIB = 1024
	MIB = 1024 * KIB
	GIB = 1024 * MIB
	TIB = 1024 * GIB
)

const (
	DEFAULT_CD2N_POOLID        = "CESS CD2N OFFICAL POOL"
	TIME_LAYOUT                = "2006/01/02 15:04:05"
	DEFAULT_GATEWAY_CACHE_SIZE = 384 * GIB
	DEFAULT_IPFS_DISK_SIZE     = 512 * GIB
	DEFAULT_BUFFER_SIZE        = 128 * GIB
	SEGMENT_SIZE               = 32 * MIB
	FRAGMENT_SIZE              = 8 * MIB
	FRAGMENTS_NUM              = 4
	PARITY_NUM                 = 8
	DEFAULT_ORDER_TRAFFIC      = 8 * GIB
	DEFAULT_GASFREECAP         = 108694000460
	DEFAULT_GASLIMIT           = 30000000
	DEFAULT_CHAINID            = 11330
	VERSION                    = "0.8.1"
)

const (
	LOG_PROVIDER = "provider"
	LOG_GATEWAY  = "gateway"
	LOG_RETRIEVE = "retrieve"
)

const (
	DEFAULT_PATH = "./config.yaml"

	DEFAULT_WORKSPACE = "./cd2n"
	FILE_CACHE_DIR    = "cache"
	DATA_BUFFER_DIR   = "buffer"
	LEVELDB_DIR       = "leveldb"
	CONF_DIR          = "conf"

	TASKDB_NAME = "task_record"

	DB_SEGMENT_PREFIX  = "segment-"
	DB_FILEPART_PREFIX = "filepart-"
	DB_FINFO_PREFIX    = "fileinfo-"
	DB_CAPSULE_PREFIX  = "capsule-"
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

func MarshalConfig(conf any) ([]byte, error) {
	return yaml.Marshal(conf)
}

func InitConfig() error {
	if conf == nil {
		return errors.New("config is nil")
	}
	if conf.FileBufferSize == 0 {
		conf.FileBufferSize = DEFAULT_BUFFER_SIZE
	} else {
		conf.FileBufferSize *= GIB
	}
	if conf.GatewayCacheSize == 0 {
		conf.GatewayCacheSize = DEFAULT_GATEWAY_CACHE_SIZE
	} else {
		conf.GatewayCacheSize *= GIB
	}
	if conf.WorkSpace == "" {
		conf.WorkSpace = DEFAULT_WORKSPACE
	}
	if conf.RechargeSize == 0 {
		conf.RechargeSize = DEFAULT_ORDER_TRAFFIC
	}
	if conf.GasFreeCap == 0 {
		conf.GasFreeCap = DEFAULT_GASFREECAP
	}
	if conf.GasLimit == 0 {
		conf.GasLimit = DEFAULT_GASLIMIT
	}
	if conf.ChainId == 0 {
		conf.ChainId = DEFAULT_CHAINID
	}
	if conf.RedisLoacl == "" {
		s := strings.Split(conf.RedisAddress, ":")
		if len(s) < 2 {
			conf.RedisLoacl = "redis_host:6379"
		}
		conf.RedisLoacl = fmt.Sprintf("redis_host:%s", s[len(s)-1])
	}
	jb, _ := json.Marshal(conf.DiskConfig)
	log.Println("init disk config:", string(jb))
	return nil
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
	if err = InitConfig(); err != nil {
		return errors.Wrap(err, "init default config error")
	}
	return nil
}

func GetConfig() Config {
	return *conf
}
