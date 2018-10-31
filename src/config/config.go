package config

import "strings"

var AWSAccountId = "111122223333"

var AWSRegion = "eu-west-2"

var DatabasePath = "/tmp/local-kms"

func ArnPrefix() string {
	return "arn:aws:kms:"+AWSRegion+":"+AWSAccountId+":"
}

func EnsureArn(prefix, target string) string {

	// If it's already an ARN
	if strings.HasPrefix(target, "arn:") {
		return target
	}

	return ArnPrefix() + prefix + target
}
