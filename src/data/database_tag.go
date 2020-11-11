package data

import (
	"encoding/json"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func (d *Database) SaveTag(k cmk.Key, t *Tag) error {
	encoded, err := json.Marshal(t)
	if err != nil {
		return err
	}

	// We save under a value of the key's ARN, plus the tag key value.
	return d.database.Put([]byte(k.GetArn()+"/tag/"+t.TagKey), encoded, nil)
}

func (d *Database) ListTags(prefix string, limit int64, marker string) (tags []*Tag, err error) {

	// The prefix is the Key's ARN, plus /tag
	iter := d.database.NewIterator(util.BytesPrefix([]byte(prefix+"/tag")), nil)

	var count int64 = 0

	pastMarker := false

	for count < limit && iter.Next() {

		// If there's a marker, and we're not already past it, and the current item does not match the marker:
		// The marker needs the Key ARN and /tag/ including
		if marker != "" && !pastMarker && prefix+"/tag/"+marker != string(iter.Key()) {
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
