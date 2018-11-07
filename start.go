package main

import (
	"os"
	"github.com/nsmithuk/local-kms/src"
	"github.com/nsmithuk/local-kms/src/config"
	"path/filepath"
)

func main() {

	accountId := os.Getenv("ACCOUNT_ID")
	if accountId == "" {
		accountId = "111122223333"
	}
	config.AWSAccountId = accountId


	region := os.Getenv("REGION")
	if region == "" {
		region = "eu-west-2"
	}
	config.AWSRegion = region


	dataPath := os.Getenv("DATA_PATH")
	if dataPath == "" {
		dataPath = "/tmp/local-kms"
	}
	config.DatabasePath, _ = filepath.Abs(dataPath)

	//-------------------------------
	// Seed

	seedPath := os.Getenv("SEED_PATH")
	src.Seed(seedPath)

	//-------------------------------
	// Run

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	src.Run(port)
}
