package data

import (
	"encoding/json"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func (d *Database) SaveAlias(a *Alias) error {
	encoded, err := json.Marshal(a)
	if err != nil {
		return err
	}

	return d.database.Put([]byte(a.AliasArn), encoded, nil)
}

func (d *Database) LoadAlias(arn string) (*Alias, error) {

	encoded, err := d.database.Get([]byte(arn), nil)

	if err != nil {
		return nil, err
	}

	//---

	var a Alias
	err = json.Unmarshal(encoded, &a)

	return &a, err
}

func (d *Database) ListAlias(prefix string, limit int64, marker, key string) (aliases []*Alias, err error) {

	iter := d.database.NewIterator(util.BytesPrefix([]byte(prefix)), nil)

	var count int64 = 0

	pastMarker := false

	for count < limit && iter.Next() {

		// If there's a marker, and we're not already past it, and the current item does not match the marker:
		if marker != "" && !pastMarker && marker != string(iter.Key()) {
			continue
		}

		pastMarker = true

		var a Alias

		err = json.Unmarshal(iter.Value(), &a)
		if err != nil {
			return
		}

		if key != "" && a.TargetKeyId != key {
			// If we're filtering by key, skip entry if the key doesn't match.
			continue
		}

		aliases = append(aliases, &a)

		count++
	}

	iter.Release()
	err = iter.Error()

	if marker != "" && !pastMarker {
		err = &InvalidMarkerExceptionError{}
	}

	return
}
