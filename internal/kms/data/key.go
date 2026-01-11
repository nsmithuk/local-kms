package data

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
)

//
// ──────────────────────────────
// Keys
// ──────────────────────────────
//

func (d Database) SaveKey(k cmk.Key) error {
	if d.db == nil {
		return errors.New("db is nil")
	}
	if k == nil {
		return errors.New("key is nil")
	}

	arn := k.GetArn()
	if arn == "" {
		return errors.New("key missing ARN")
	}

	b, err := json.Marshal(k)
	if err != nil {
		return err
	}

	return d.db.Set(keyKey(arn), b, pebble.NoSync)
}

func (d Database) DeleteKey(k cmk.Key) error {
	if d.db == nil {
		return errors.New("db is nil")
	}
	if k == nil {
		return errors.New("key is nil")
	}

	arn := k.GetArn()
	if arn == "" {
		return errors.New("key missing ARN")
	}

	if err := d.db.Delete(keyKey(arn), pebble.NoSync); err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return err
	}

	// Delete all tags for this key
	tagPrefix := tagPrefixForKey(arn)

	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: tagPrefix,
		UpperBound: prefixEnd(tagPrefix),
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		// Make a copy of the key since iter.Key() is only valid until Next().
		kcopy := append([]byte(nil), iter.Key()...)
		if err := d.db.Delete(kcopy, pebble.NoSync); err != nil && !errors.Is(err, pebble.ErrNotFound) {
			return err
		}
	}

	return iter.Error()
}

// LoadKey: because cmk.Key is an interface, caller provides the concrete destination.
func (d Database) LoadKey(arn string) (cmk.Key, error) {
	if d.db == nil {
		return nil, errors.New("db is nil")
	}
	if arn == "" {
		return nil, errors.New("arn is empty")
	}

	val, closer, err := d.db.Get(keyKey(arn))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, arn)
		}
		return nil, err
	}
	defer closer.Close()

	var aux struct {
		KeyType cmk.KeyType `json:"KeyType"`
	}
	err = json.Unmarshal(val, &aux)
	if err != nil {
		return nil, err
	}

	key, err := cmk.GetKeyType(aux.KeyType)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(val, key)

	//---

	if key.ShouldBeDeleted() {
		err := d.DeleteKey(key)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s has already been deleted.", ErrKeyNotFound, arn)
	}

	//---

	if sk, ok := key.(*cmk.SymmetricKey); ok {
		if rotated := sk.RotateIfNeeded(); rotated {
			err := d.SaveKey(sk)
			if err != nil {
				return nil, err
			}
		}
	}

	//---

	return key, err
}

func (d Database) ListKeys(limit int32, marker *string) ([]cmk.Key, error) {
	if d.db == nil {
		return nil, errors.New("db is nil")
	}
	if limit <= 0 {
		limit = 100
	}

	// We want all keys
	dbPrefix := keyPrefix("")

	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: dbPrefix,
		UpperBound: prefixEnd(dbPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	if marker != nil {
		markerPrefix := keyPrefix(*marker)
		iter.SeekGE(markerPrefix)
		keyFound := string(iter.Key())
		if iter.Valid() && keyFound == string(markerPrefix) {
			iter.Next()
		} else {
			return nil, fmt.Errorf("%w: %s", ErrInvalidMarker, *marker)
		}
	} else {
		iter.First()
	}

	out := make([]cmk.Key, 0, limit)
	for ; iter.Valid(); iter.Next() {
		val, err := iter.ValueAndErr()
		if err != nil {
			return nil, err
		}

		var aux struct {
			KeyType cmk.KeyType `json:"KeyType"`
		}
		err = json.Unmarshal(val, &aux)
		if err != nil {
			return nil, err
		}

		key, err := cmk.GetKeyType(aux.KeyType)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(val, key)
		if err != nil {
			return nil, err
		}

		//---

		if key.ShouldBeDeleted() {
			err := d.DeleteKey(key)
			if err != nil {
				return nil, err
			}
			continue
		}

		//---

		out = append(out, key)
		if int32(len(out)) >= limit {
			break
		}
	}

	return out, iter.Error()
}
