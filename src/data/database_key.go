package data

import (
	"encoding/json"
	"errors"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"strings"
	"time"
)

func (d *Database) SaveKey(k cmk.Key) error {
	encoded, err := json.Marshal(k)
	if err != nil {
		return err
	}

	return d.database.Put([]byte(k.GetArn()), encoded, nil)
}

func (d *Database) LoadKey(arn string) (cmk.Key, error) {

	encoded, err := d.database.Get( []byte(arn), nil )

	if err != nil {
		return nil, err
	}

	//---

	key, err := unmarshalKey(encoded)
	if err != nil {
		return nil, err
	}

	//---

	switch k := key.(type) {
	case *cmk.AesKey:

		// Rotate the key, if needed
		if rotated := k.RotateIfNeeded(); rotated {
			d.SaveKey(k)
		}

		key = k
	default:
		return nil, errors.New("key type not yet supported")
	}

	//---

	// Delete key if it has expired
	if key.GetMetadata().DeletionDate != 0 && key.GetMetadata().DeletionDate < time.Now().Unix() {
		d.DeleteObject(arn)
		return nil, leveldb.ErrNotFound
	}

	//---

	return key, err
}

/*
	Returns all keys.
		If limit is set, only that given number of keys are returned.
		If marker is set, only key with match, and come after, the marker key are returned. i.e. an 'offset'.
*/
func (d *Database) ListKeys(prefix string, limit int64, marker string) (keys []cmk.Key, err error) {

	iter := d.database.NewIterator(util.BytesPrefix([]byte(prefix)), nil)

	var count int64 = 0

	pastMarker := false

	for count < limit && iter.Next() {

		// Exclude tags
		if strings.Contains(string(iter.Key()), "/tag/") {
			continue
		}

		// If there's a marker, and we're not already past it, and the current item does not match the marker:
		if marker != "" && !pastMarker && marker != string(iter.Key()) {
			continue
		}

		pastMarker = true

		key, err := unmarshalKey(iter.Value())
		if err != nil {
			return nil, err
		}

		// Delete key if it has expired
		if key.GetMetadata().DeletionDate != 0 && key.GetMetadata().DeletionDate < time.Now().Unix() {
			d.DeleteObject(key.GetArn())
			continue
		}

		keys = append(keys, key)

		count++
	}

	iter.Release()
	err = iter.Error()

	if marker != "" && !pastMarker {
		err = &InvalidMarkerExceptionError{}
	}

	return
}

func unmarshalKey(encoded []byte) (cmk.Key, error) {

	//---------------------------------------------------------
	// Unmarshal just the key's type

	var kt struct{
		Type cmk.KeyType
	}

	err := json.Unmarshal(encoded, &kt)
	if err != nil {
		return nil, err
	}

	//---------------------------------------------------------
	// Unmarshal the full key, with the correct Implementation

	var key cmk.Key

	switch kt.Type {
	case cmk.TypeAes:
		key = new(cmk.AesKey)
	default:
		return nil, errors.New("key type not yet supported")
	}

	err = json.Unmarshal(encoded, &key)

	return key, err
}
