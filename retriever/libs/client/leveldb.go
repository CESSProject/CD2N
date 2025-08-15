package client

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
)

var (
	dbPool map[string]*leveldb.DB
)

func RegisterLeveldbCli(dir string, names ...string) error {
	if dbPool == nil {
		dbPool = make(map[string]*leveldb.DB)
	}
	if _, err := os.Stat(dir); err != nil {
		if err = os.MkdirAll(dir, 0755); err != nil {
			return errors.Wrap(err, "register leveldb client error")
		}
	}
	for _, name := range names {
		db, err := NewDB(filepath.Join(dir, name))
		if err != nil {
			return errors.Wrap(err, "register leveldb client error")
		}
		dbPool[name] = db
	}
	return nil
}

func GetLeveldbCli(name string) *leveldb.DB {
	if dbPool == nil {
		dbPool = make(map[string]*leveldb.DB)
	}
	return dbPool[name]
}

func NewDB(path string) (*leveldb.DB, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, errors.Wrap(err, "new leveldb error")
	}
	return db, nil
}

func GetData(db *leveldb.DB, key string, value any) error {
	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return errors.Wrap(err, "get data from leveldb error")
	}
	err = json.Unmarshal(data, value)
	if err != nil {
		log.Println("unmarshal data from leveldb error, data:", string(data))
		return errors.Wrap(err, "get data from leveldb error")
	}
	return nil
}

func PutData(db *leveldb.DB, key string, value any) error {
	jbytes, err := json.Marshal(value)
	if err != nil {
		return errors.Wrap(err, "put data to leveldb error")
	}
	err = db.Put([]byte(key), jbytes, nil)
	if err != nil {
		return errors.Wrap(err, "put data to leveldb error")
	}
	return nil
}

func GetBytes(db *leveldb.DB, key string) ([]byte, error) {
	data, err := db.Get([]byte(key), nil)
	if err != nil {
		return nil, errors.Wrap(err, "get bytes data from leveldb error")
	}
	return data, nil
}

func PutBytes(db *leveldb.DB, key string, data []byte) error {
	err := db.Put([]byte(key), data, nil)
	if err != nil {
		return errors.Wrap(err, "put bytes data to leveldb error")
	}
	return nil
}

func DeleteData(db *leveldb.DB, key string) error {
	err := db.Delete([]byte(key), nil)
	if err != nil {
		return errors.Wrap(err, "delete data to leveldb error")
	}
	return nil
}

func DbIterator(db *leveldb.DB, handle func([]byte) error) error {
	iter := db.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		if err := handle(iter.Key()); err != nil {
			return errors.Wrap(err, "iterating data error")
		}
		if err := iter.Error(); err != nil {
			return errors.Wrap(err, "iterating data error")
		}
	}
	return nil
}
