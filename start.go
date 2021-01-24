package main

import (
	"github.com/nsmithuk/local-kms/src"
	"github.com/nsmithuk/local-kms/src/config"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
)

var (
	Version string
	GitCommit string
)

func main() {

	logger := log.New()

	logger.SetFormatter(&log.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05.000",
	})

	//---

	if Version == "" {
		Version = "Version Unknown"
	}

	if GitCommit == "" {
		GitCommit = "Commit Hash Unknown"
	}

	logger.Infof("Local KMS %s (%s)", Version, GitCommit)

	//---

	accountId := os.Getenv("KMS_ACCOUNT_ID")

	if accountId == "" {
		// Environment variables should now all be prefixed with KMS_. Support for variables without this prefix will be removed in v4.
		accountId = os.Getenv("ACCOUNT_ID")
		if accountId != "" {
			logger.Warn("The environment variable ACCOUNT_ID has been deprecated and will be removed in v4. Use KMS_ACCOUNT_ID instead.")
		}
	}

	if accountId == "" {
		accountId = "111122223333"
	}
	config.AWSAccountId = accountId

	region := os.Getenv("KMS_REGION")

	if region == "" {
		// Environment variables should now all be prefixed with KMS_. Support for variables without this prefix will be removed in v4.
		region = os.Getenv("REGION")
		if region != "" {
			logger.Warn("The environment variable REGION has been deprecated and will be removed in v4. Use KMS_REGION instead.")
		}
	}

	if region == "" {
		region = "eu-west-2"
	}
	config.AWSRegion = region

	dataPath := os.Getenv("KMS_DATA_PATH")
	if dataPath == "" {
		// Environment variables should now all be prefixed with KMS_. Support for variables without this prefix will be removed in v4.
		dataPath = os.Getenv("DATA_PATH")
		if dataPath != "" {
			logger.Warn("The environment variable DATA_PATH has been deprecated and will be removed in v4. Use KMS_DATA_PATH instead.")
		}
	}

	if dataPath == "" {
		dataPath = "/tmp/local-kms"
	}

	config.DatabasePath, _ = filepath.Abs(dataPath)

	//-------------------------------
	// Seed

	seedPath := os.Getenv("KMS_SEED_PATH")

	if seedPath == "" {
		// Environment variables should now all be prefixed with KMS_. Support for variables without this prefix will be removed in v4.
		seedPath = os.Getenv("SEED_PATH")
		if seedPath != "" {
			logger.Warn("The environment variable SEED_PATH has been deprecated and will be removed in v4. Use KMS_SEED_PATH instead.")
		}
	}

	if seedPath == "" {
		seedPath = "/init/seed.yaml"
	}

	//-------------------------------
	// Run

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	src.Run(port, seedPath)
}
