package data

import (
	"github.com/syndtr/goleveldb/leveldb"
)

type Database struct {
	database *leveldb.DB
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

type InvalidMarkerExceptionError struct{}

func (e *InvalidMarkerExceptionError) Error() string {
	return "Invalid marker"
}

//------------------------------------

// Can delete any object type. e.g. key, alias, etc.
func (d *Database) DeleteObject(arn string) error {
	return d.database.Delete([]byte(arn), nil)
}
