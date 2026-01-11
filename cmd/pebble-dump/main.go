package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cockroachdb/pebble"
)

func main() {
	dataPath := os.Getenv("KMS_DATA_PATH")
	if dataPath == "" {
		panic("KMS_DATA_PATH environment variable not set")
	}

	db, err := pebble.Open(dataPath, &pebble.Options{
		ReadOnly: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	iter, err := db.NewIter(nil)
	if err != nil {
		log.Fatal(err)
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		fmt.Printf("key=%s value=%s\n", iter.Key(), iter.Value())
	}
	if err := iter.Error(); err != nil {
		log.Fatal(err)
	}
}
