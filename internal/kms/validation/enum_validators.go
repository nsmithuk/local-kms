package validation

import (
	awskmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func (*Validator) ExpirationModel(value awskmstypes.ExpirationModelType) error {
	return ValidateEnum(value, "ExpirationModel")
}

func (*Validator) ImportType(value awskmstypes.ImportType) error {
	return ValidateEnum(value, "ImportType")
}

func (*Validator) WrappingKeySpec(value awskmstypes.WrappingKeySpec) error {
	return ValidateEnum(value, "WrappingKeySpec")
}

func (*Validator) WrappingAlgorithm(value awskmstypes.AlgorithmSpec) error {
	return ValidateEnum(value, "WrappingAlgorithm")
}
