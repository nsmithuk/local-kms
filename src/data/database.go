package data

import (
	"encoding/json"
	"github.com/nsmithuk/local-kms/src/service"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"time"
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

type InvalidMarkerExceptionError struct {}

func (e *InvalidMarkerExceptionError) Error() string {
	return "Invalid marker"
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

func (d *Database) SaveAlias(a *Alias) error {
	encoded, err := json.Marshal(a)
	if err != nil {
		return err
	}

	return d.database.Put( []byte(a.AliasArn), encoded, nil )
}

func (d *Database) SaveTag(k *Key, t *Tag) error {
	encoded, err := json.Marshal(t)
	if err != nil {
		return err
	}

	// We save under a value of the key's ARN, plus the tag key value.
	return d.database.Put( []byte(k.Metadata.Arn + "/tag/" + t.TagKey), encoded, nil )
}

//---

func (d *Database) LoadKey(arn string) (*Key, error) {

	encoded, err := d.database.Get( []byte(arn), nil )

	if err != nil {
		return nil, err
	}

	//---

	var k Key
	err = json.Unmarshal(encoded, &k)

	// Delete key if it has expired
	if k.Metadata.DeletionDate != 0 && k.Metadata.DeletionDate < time.Now().Unix() {
		d.DeleteObject(arn)
		return nil, leveldb.ErrNotFound
	}

	//---

	// Check if key needs rotating
	if k.Metadata.Enabled && !k.NextKeyRotation.IsZero() && k.NextKeyRotation.Before(time.Now()) {

		// Add a new backing key to use
		k.BackingKeys = append(k.BackingKeys, service.GenerateNewKey())

		// Reset the timer
		k.NextKeyRotation = time.Now().AddDate(1, 0, 0)

		d.SaveKey(&k)
	}

	//---

	return &k, err
}

func (d *Database) LoadAlias(arn string) (*Alias, error) {

	encoded, err := d.database.Get( []byte(arn), nil )

	if err != nil {
		return nil, err
	}

	//---

	var a Alias
	err = json.Unmarshal(encoded, &a)

	return &a, err
}

//---

// Can delete any object type. e.g. key, alias, etc.
func (d *Database) DeleteObject(arn string) error {
	return d.database.Delete([]byte(arn), nil)
}

//---

/*
	Returns all keys.
		If limit is set, only that given number of keys are returned.
		If marker is set, only key with match, and come after, the marker key are returned. i.e. an 'offset'.
*/
func (d *Database) ListKeys(prefix string, limit int64, marker string) (keys []*Key, err error) {

	iter := d.database.NewIterator(util.BytesPrefix([]byte(prefix)), nil)

	var count int64 = 0

	pastMarker := false

	for count < limit && iter.Next() {

		// If there's a marker, and we're not already past it, and the current item does not match the marker:
		if marker != "" && !pastMarker && marker != string(iter.Key()) {
			continue
		}

		pastMarker = true

		var k Key

		err = json.Unmarshal(iter.Value(), &k)
		if err != nil {
			return
		}

		// Delete key if it has expired
		if k.Metadata.DeletionDate != 0 && k.Metadata.DeletionDate < time.Now().Unix() {
			d.DeleteObject(k.Metadata.Arn)
			continue
		}

		keys = append(keys, &k)

		count++
	}

	iter.Release()
	err = iter.Error()

	if marker != "" && !pastMarker {
		err = &InvalidMarkerExceptionError{}
	}

	return
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

func (d *Database) ListTags(prefix string, limit int64, marker string) (tags []*Tag, err error) {

	// The prefix is the Key's ARN, plus /tag
	iter := d.database.NewIterator(util.BytesPrefix([]byte(prefix + "/tag")), nil)

	var count int64 = 0

	pastMarker := false

	for count < limit && iter.Next() {

		// If there's a marker, and we're not already past it, and the current item does not match the marker:
		// The marker needs the Key ARN and /tag/ including
		if marker != "" && !pastMarker && prefix + "/tag/" + marker != string(iter.Key()) {
			continue
		}

		pastMarker = true

		var t Tag

		err = json.Unmarshal(iter.Value(), &t)
		if err != nil {
			return
		}

		tags = append(tags, &t)

		count++
	}

	iter.Release()
	err = iter.Error()

	if marker != "" && !pastMarker {
		err = &InvalidMarkerExceptionError{}
	}

	return
}
