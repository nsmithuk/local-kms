package config

var AWSAccountId = "111122223333"

var AWSRegion = "eu-west-2"

var DatabasePath = "/tmp/local-kms"

func ArnPrefix() string {
	return "arn:aws:kms:"+AWSRegion+":"+AWSAccountId+":"
}
