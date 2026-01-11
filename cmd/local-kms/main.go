package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nsmithuk/local-kms/internal/httpapi"
	"github.com/nsmithuk/local-kms/internal/kms"
	"github.com/nsmithuk/local-kms/internal/seed"
)

var (
	Version   string
	GitCommit string
)

func main() {

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.String("time",
					a.Value.Time().Format("2006-01-02 15:04:05.000"),
				)
			}
			return a
		},
	})

	logger := slog.New(handler)
	slog.SetDefault(logger)

	//---

	if Version == "" {
		Version = "Version Unknown"
	}

	if GitCommit == "" {
		GitCommit = "Commit Hash Unknown"
	}

	//-------------------------------
	// AWS Config

	accountId := os.Getenv("KMS_ACCOUNT_ID")
	if accountId == "" {
		accountId = "111122223333"
	}

	//---

	region := os.Getenv("KMS_REGION")
	if region == "" {
		region = "eu-west-2"
	}

	//-------------------------------
	// Data

	dataPath := os.Getenv("KMS_DATA_PATH")
	if dataPath == "" {
		dataPath = "/tmp/local-kms"
	}

	//-------------------------------
	// Run

	slog.Info("Local KMS starting",
		"version", Version,
		"commit", GitCommit,
		"account", accountId,
		"region", region,
		"data", dataPath,
	)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	//---

	//
	//kmsService := kms.KmsService{
	//	AWSRegion:    region,
	//	AWSAccountId: accountId,
	//	Database:     db,
	//}

	kmsService, err := kms.NewKmsService(region, accountId, dataPath)
	defer kmsService.Close()

	//---

	seedPath := os.Getenv("KMS_SEED_PATH")
	if seedPath != "" {
		slog.Info("Seeding from",
			"path", seedPath,
		)

		seeder := seed.NewSeeder(kmsService)
		_ = seeder.Seed(seedPath)
		seeder = nil
	}

	//---

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := httpapi.NewServer(kmsService)

	err = server.Start(ctx, port)
	if err != nil {
		log.Fatal(err)
	}
}
