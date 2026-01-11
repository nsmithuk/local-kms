package seed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/internal/kms"
	"github.com/nsmithuk/local-kms/internal/kms/cmk"
	"github.com/nsmithuk/local-kms/internal/kms/data"
	"gopkg.in/yaml.v3"
)

//----------------------------------------------------
// Input format

type Config struct {
	Version int     `yaml:"Version"`
	Aliases []Alias `yaml:"Aliases,omitempty"`
	Keys    []Key   `yaml:"Keys"`
}

type Alias struct {
	AliasName   string `yaml:"AliasName"`
	TargetKeyId string `yaml:"TargetKeyId"`
}

type Key struct {
	KeyId string `yaml:"KeyId"`
	//Type            string      `yaml:"Type"`               // e.g. symmetric, ecdsa, rsa
	Metadata        KeyMetadata            `yaml:"Metadata"` // optional fields inside may be empty
	NextKeyRotation *time.Time             `yaml:"NextKeyRotation,omitempty"`
	Material        cmk.SeedingKeyMaterial `yaml:"Material"` // varies per key type
}

type KeyMetadata struct {
	Description *string            `yaml:"Description,omitempty"`
	KeySpec     types.KeySpec      `yaml:"KeySpec"`
	KeyUsage    types.KeyUsageType `yaml:"KeyUsage,omitempty"`
}

func (m *KeyMetadata) getCreateKeyInput() awskms.CreateKeyInput {
	return awskms.CreateKeyInput{
		Description: m.Description,
		KeySpec:     m.KeySpec,
		KeyUsage:    m.KeyUsage,
	}
}

//----------------------------------------------------

type Seeder struct {
	ksmService *kms.KmsService
}

func NewSeeder(kmsService *kms.KmsService) *Seeder {
	return &Seeder{ksmService: kmsService}
}

func (s *Seeder) Seed(seedPath string) error {

	config, err := getInput(seedPath)
	if err != nil {
		return err
	}

	for _, key := range config.Keys {
		cmk, errs := s.ksmService.CreateKeyWithoutMaterial(context.TODO(), key.Metadata.getCreateKeyInput(), key.KeyId)
		if errs != nil {
			return fmt.Errorf("Errors found when seeding: %v", errs)
		}

		//---

		_, err := s.ksmService.Db.LoadKey(cmk.GetArn())
		if !errors.Is(err, data.ErrKeyNotFound) {
			slog.Info("Key from seed file is already in the database; skipping",
				"arn", cmk.GetArn(),
				"keyspec", cmk.GetMetadata().KeySpec,
			)
			continue
		}

		//---

		err = cmk.ApplySeedingKeyMaterial(key.Material)
		if err != nil {
			return err
		}

		err = s.ksmService.Db.SaveKey(cmk)
		if err != nil {
			return err
		}
	}

	//---

	now := time.Now()

	for _, alias := range config.Aliases {
		aliasArn := s.ksmService.ArnPrefix() + "alias/" + strings.TrimPrefix(alias.AliasName, "alias/")
		_, err = s.ksmService.Db.LoadAlias(aliasArn)
		if !errors.Is(err, data.ErrAliasNotFound) {
			slog.Info("Alias from seed file is already in the database; skipping",
				"arn", aliasArn,
			)
			continue
		}

		targetKeyArn, err := s.ksmService.ResolveKeyArn(&alias.TargetKeyId)
		if err != nil {
			return err
		}

		_, err = s.ksmService.Db.LoadKey(targetKeyArn)
		if err != nil {
			return err
		}

		//---

		a := types.AliasListEntry{
			AliasArn:        &aliasArn,
			AliasName:       &alias.AliasName,
			CreationDate:    &now,
			LastUpdatedDate: &now,
			TargetKeyId:     &targetKeyArn,
		}

		if err := s.ksmService.Db.SaveAlias(a); err != nil {
			return err
		}
	}

	return nil
}

func getInput(seedPath string) (*Config, error) {

	path, err := filepath.Abs(seedPath)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("No file found at path %s; skipping seeding.", path)
	} else if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	seed := Config{}

	if err = yaml.Unmarshal(data, &seed); err != nil {
		return nil, err
	}

	return &seed, nil
}
