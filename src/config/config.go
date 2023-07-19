package config

import (
	"strings"

	"github.com/nsmithuk/local-kms/src/iam"
)

var AWSRegion string
var AWSAccountId string
var DatabasePath string
var IAM iam.IdentityAccessManagement

func ArnPrefix(accountId string) string {
	return "arn:aws:kms:" + AWSRegion + ":" + accountId + ":"
}

func EnsureArn(prefix, accountId, target string) string {

	// If it's already an ARN
	if strings.HasPrefix(target, "arn:") {
		return target
	}

	return ArnPrefix(accountId) + prefix + target
}
