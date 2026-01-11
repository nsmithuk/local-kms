package kms

import (
	"errors"
	"strings"

	"github.com/cockroachdb/pebble"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

type KmsService struct {
	AWSRegion    string
	AWSAccountId string
	Db           data.Database
}

func NewKmsService(region, accountId, dbPath string) (*KmsService, error) {
	db, err := pebble.Open(dbPath, &pebble.Options{})
	if err != nil {
		return nil, err
	}

	return &KmsService{
		AWSRegion:    region,
		AWSAccountId: accountId,
		Db:           data.NewDatabase(db),
	}, nil
}

func (k KmsService) Close() error {
	return k.Db.Close()
}

func (k KmsService) ResolveKeyArn(keyId *string) (string, error) {
	if keyId == nil {
		return "", kmserr.NewValidation(kmserr.CauseValidationError, "'KeyId' is a required field")
	}

	if strings.HasPrefix(*keyId, "alias/") || strings.HasPrefix(*keyId, k.ArnPrefix()+"alias/") {
		aliasArn := *keyId

		if !strings.HasPrefix(aliasArn, "arn:") {
			aliasArn = k.ArnPrefix() + "alias/" + strings.TrimPrefix(aliasArn, "alias/")
		}

		alias, err := k.Db.LoadAlias(aliasArn)
		if err != nil {
			if errors.Is(err, data.ErrAliasNotFound) {
				return "", kmserr.NewValidation(kmserr.CauseNotFoundException, "Alias %s not found", aliasArn)
			}
			return "", err
		}

		if alias.TargetKeyId == nil || *alias.TargetKeyId == "" {
			return "", kmserr.NewValidation(kmserr.CauseNotFoundException, "Alias %s has no target key", aliasArn)
		}

		return *alias.TargetKeyId, nil
	}

	if strings.HasPrefix(*keyId, "arn:") {
		return *keyId, nil
	}

	return k.ArnPrefix() + "key/" + *keyId, nil
}

func (k KmsService) ArnPrefix() string {
	return "arn:aws:kms:" + k.AWSRegion + ":" + k.AWSAccountId + ":"
}
