package data

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cockroachdb/pebble"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
)

var ErrKeyNotFound = errors.New("key not found")
var ErrAliasNotFound = errors.New("alias not found")
var ErrInvalidMarker = errors.New("the passed marker is invalid")

type Database struct {
	db *pebble.DB
}

func NewDatabase(db *pebble.DB) Database {
	return Database{db: db}
}

func (d Database) Close() error {
	if d.db == nil {
		return nil
	}
	return d.db.Close()
}

//
// ──────────────────────────────
// Aliases
// ──────────────────────────────
//

func (d Database) SaveAlias(a types.AliasListEntry) error {
	if d.db == nil {
		return errors.New("db is nil")
	}
	if a.AliasArn == nil || *a.AliasArn == "" {
		return errors.New("alias missing AliasArn")
	}

	b, err := json.Marshal(a)
	if err != nil {
		return err
	}

	return d.db.Set(aliasKey(*a.AliasArn), b, pebble.NoSync)
}

func (d Database) DeleteAlias(a types.AliasListEntry) error {
	if d.db == nil {
		return errors.New("db is nil")
	}
	if a.AliasArn == nil || *a.AliasArn == "" {
		return errors.New("alias missing AliasArn")
	}

	err := d.db.Delete(aliasKey(*a.AliasArn), pebble.NoSync)
	if errors.Is(err, pebble.ErrNotFound) {
		return nil
	}
	return err
}

func (d Database) LoadAlias(arn string) (types.AliasListEntry, error) {
	var out types.AliasListEntry
	if d.db == nil {
		return out, errors.New("db is nil")
	}
	if arn == "" {
		return out, errors.New("arn is empty")
	}

	val, closer, err := d.db.Get(aliasKey(arn))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return out, fmt.Errorf("%w: %s", ErrAliasNotFound, arn)
		}
		return out, err
	}
	defer closer.Close()

	if err := json.Unmarshal(val, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (d Database) ListAlias(prefix string, limit int64, marker, key string) ([]types.AliasListEntry, error) {
	if d.db == nil {
		return nil, errors.New("db is nil")
	}
	if limit <= 0 {
		limit = 100
	}

	dbPrefix := aliasPrefix(prefix)

	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: dbPrefix,
		UpperBound: prefixEnd(dbPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	if marker != "" {
		iter.SeekGE([]byte(marker))
		if iter.Valid() && string(iter.Key()) == marker {
			iter.Next()
		}
	} else {
		iter.First()
	}

	var out []types.AliasListEntry
	for ; iter.Valid(); iter.Next() {
		var a types.AliasListEntry
		if err := json.Unmarshal(iter.Value(), &a); err != nil {
			return nil, err
		}

		if key != "" {
			if a.TargetKeyId == nil || *a.TargetKeyId != key {
				continue
			}
		}

		out = append(out, a)
		if int64(len(out)) >= limit {
			break
		}
	}

	return out, iter.Error()
}

//
// ──────────────────────────────
// Tags
// ──────────────────────────────
//

func (d Database) SaveTag(k cmk.Key, t types.Tag) error {
	if d.db == nil {
		return errors.New("db is nil")
	}
	if k == nil {
		return errors.New("key is nil")
	}
	if t.TagKey == nil || *t.TagKey == "" {
		return errors.New("tag missing TagKey")
	}

	b, err := json.Marshal(t)
	if err != nil {
		return err
	}

	return d.db.Set(tagKey(k.GetArn(), *t.TagKey), b, pebble.NoSync)
}

// DeleteTag deletes ALL tags for the key (signature has no tag key, so this is the least surprising behaviour).
func (d Database) DeleteTag(k cmk.Key) error {
	if d.db == nil {
		return errors.New("db is nil")
	}
	if k == nil {
		return errors.New("key is nil")
	}

	prefix := tagPrefixForKey(k.GetArn())

	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: prefixEnd(prefix),
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		kcopy := append([]byte(nil), iter.Key()...)
		if err := d.db.Delete(kcopy, pebble.NoSync); err != nil && !errors.Is(err, pebble.ErrNotFound) {
			return err
		}
	}

	return iter.Error()
}

func (d Database) ListTags(prefix string, limit int64, marker string) ([]*types.Tag, error) {
	if d.db == nil {
		return nil, errors.New("db is nil")
	}
	if limit <= 0 {
		limit = 100
	}

	dbPrefix := tagPrefixForKey(prefix)

	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: dbPrefix,
		UpperBound: prefixEnd(dbPrefix),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	if marker != "" {
		iter.SeekGE([]byte(marker))
		if iter.Valid() && string(iter.Key()) == marker {
			iter.Next()
		}
	} else {
		iter.First()
	}

	var out []*types.Tag
	for ; iter.Valid(); iter.Next() {
		var t types.Tag
		if err := json.Unmarshal(iter.Value(), &t); err != nil {
			return nil, err
		}
		tt := t
		out = append(out, &tt)
		if int64(len(out)) >= limit {
			break
		}
	}

	return out, iter.Error()
}
