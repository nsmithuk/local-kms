package data

import(
	"github.com/syndtr/goleveldb/leveldb"
	"encoding/json"
)

type Database struct {
	database	*leveldb.DB
}

func NewDatabase(path string) *Database {

	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		panic(err)
	}

	return &Database{
		database: db,
	}
}

func (d *Database) Close() {
	d.database.Close()
}

//------------------------------------
// Save Key

func (d *Database) SaveKey(k *Key) error {

	encoded, err := json.Marshal(k)
	if err != nil {
		return err
	}

	return d.database.Put( []byte(k.Metadata.Arn), encoded, nil )
}
