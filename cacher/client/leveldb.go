package client

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
)

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

func DeleteData(db *leveldb.DB, key string) error {
	err := db.Delete([]byte(key), nil)
	if err != nil {
		return errors.Wrap(err, "delete data to leveldb error")
	}
	return nil
}
