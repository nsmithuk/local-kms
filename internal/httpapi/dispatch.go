package httpapi

import (
	"context"
	"encoding/json"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	jsoniter "github.com/json-iterator/go"
	"github.com/nsmithuk/local-kms/internal/kms"
)

type kmsHandler func(ctx context.Context, body []byte) (any, []error)

func buildDispatcher(kms *kms.KmsService) map[string]kmsHandler {
	return map[string]kmsHandler{
		//"CancelKeyDeletion": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.CancelKeyDeletionInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.CancelKeyDeletion(ctx, in)
		//},
		//"ConnectCustomKeyStore": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.ConnectCustomKeyStoreInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.ConnectCustomKeyStore(ctx, in)
		//},
		"CreateAlias": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.CreateAliasInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.CreateAlias(ctx, in)
		},
		//"CreateCustomKeyStore": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.CreateCustomKeyStoreInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.CreateCustomKeyStore(ctx, in)
		//},
		//"CreateGrant": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.CreateGrantInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.CreateGrant(ctx, in)
		//},
		"CreateKey": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.CreateKeyInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.CreateKey(ctx, in)
		},
		"Decrypt": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.DecryptInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.Decrypt(ctx, in)
		},
		"DeleteAlias": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.DeleteAliasInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.DeleteAlias(ctx, in)
		},
		//"DeleteCustomKeyStore": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.DeleteCustomKeyStoreInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.DeleteCustomKeyStore(ctx, in)
		//},
		"DeleteImportedKeyMaterial": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.DeleteImportedKeyMaterialInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.DeleteImportedKeyMaterial(ctx, in)
		},
		"DeriveSharedSecret": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.DeriveSharedSecretInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.DeriveSharedSecret(ctx, in)
		},
		//"DescribeCustomKeyStores": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.DescribeCustomKeyStoresInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.DescribeCustomKeyStores(ctx, in)
		//},
		"DescribeKey": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.DescribeKeyInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.DescribeKey(ctx, in)
		},
		//"DisableKey": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.DisableKeyInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.DisableKey(ctx, in)
		//},
		//"DisableKeyRotation": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.DisableKeyRotationInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.DisableKeyRotation(ctx, in)
		//},
		//"DisconnectCustomKeyStore": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.DisconnectCustomKeyStoreInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.DisconnectCustomKeyStore(ctx, in)
		//},
		//"EnableKey": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.EnableKeyInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.EnableKey(ctx, in)
		//},
		//"EnableKeyRotation": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.EnableKeyRotationInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.EnableKeyRotation(ctx, in)
		//},
		"Encrypt": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.EncryptInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.Encrypt(ctx, in)
		},
		"GenerateDataKey": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.GenerateDataKeyInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.GenerateDataKey(ctx, in)
		},
		"GenerateDataKeyPair": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.GenerateDataKeyPairInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.GenerateDataKeyPair(ctx, in)
		},
		"GenerateDataKeyPairWithoutPlaintext": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.GenerateDataKeyPairWithoutPlaintextInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.GenerateDataKeyPairWithoutPlaintext(ctx, in)
		},
		"GenerateDataKeyWithoutPlaintext": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.GenerateDataKeyWithoutPlaintextInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.GenerateDataKeyWithoutPlaintext(ctx, in)
		},
		"GenerateMac": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.GenerateMacInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.GenerateMac(ctx, in)
		},
		"GenerateRandom": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.GenerateRandomInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.GenerateRandom(ctx, in)
		},
		//"GetKeyPolicy": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.GetKeyPolicyInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.GetKeyPolicy(ctx, in)
		//},
		//"GetKeyRotationStatus": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.GetKeyRotationStatusInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.GetKeyRotationStatus(ctx, in)
		//},
		"GetParametersForImport": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.GetParametersForImportInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.GetParametersForImport(ctx, in)
		},
		"GetPublicKey": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.GetPublicKeyInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.GetPublicKey(ctx, in)
		},
		"ImportKeyMaterial": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.ImportKeyMaterialInput
			if err := jsoniter.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.ImportKeyMaterial(ctx, in)
		},
		//"ListAliases": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.ListAliasesInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.ListAliases(ctx, in)
		//},
		//"ListGrants": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.ListGrantsInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.ListGrants(ctx, in)
		//},
		//"ListKeyPolicies": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.ListKeyPoliciesInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.ListKeyPolicies(ctx, in)
		//},
		//"ListKeyRotations": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.ListKeyRotationsInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.ListKeyRotations(ctx, in)
		//},
		"ListKeys": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.ListKeysInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.ListKeys(ctx, in)
		},
		//"ListResourceTags": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.ListResourceTagsInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.ListResourceTags(ctx, in)
		//},
		//"ListRetirableGrants": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.ListRetirableGrantsInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.ListRetirableGrants(ctx, in)
		//},
		//"PutKeyPolicy": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.PutKeyPolicyInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.PutKeyPolicy(ctx, in)
		//},
		"ReEncrypt": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.ReEncryptInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.ReEncrypt(ctx, in)
		},
		//"ReplicateKey": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.ReplicateKeyInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.ReplicateKey(ctx, in)
		//},
		//"RetireGrant": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.RetireGrantInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.RetireGrant(ctx, in)
		//},
		//"RevokeGrant": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.RevokeGrantInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.RevokeGrant(ctx, in)
		//},
		"RotateKeyOnDemand": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.RotateKeyOnDemandInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.RotateKeyOnDemand(ctx, in)
		},
		"ScheduleKeyDeletion": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.ScheduleKeyDeletionInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.ScheduleKeyDeletion(ctx, in)
		},
		"Sign": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.SignInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.Sign(ctx, in)
		},
		//"TagResource": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.TagResourceInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.TagResource(ctx, in)
		//},
		//"UntagResource": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.UntagResourceInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.UntagResource(ctx, in)
		//},
		//"UpdateAlias": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.UpdateAliasInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.UpdateAlias(ctx, in)
		//},
		//"UpdateCustomKeyStore": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.UpdateCustomKeyStoreInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.UpdateCustomKeyStore(ctx, in)
		//},
		//"UpdateKeyDescription": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.UpdateKeyDescriptionInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.UpdateKeyDescription(ctx, in)
		//},
		//"UpdatePrimaryRegion": func(ctx context.Context, body []byte) (any, []error) {
		//	var in awskms.UpdatePrimaryRegionInput
		//	if err := json.Unmarshal(body, &in); err != nil {
		//		return nil, []error{err}
		//	}
		//	return kms.UpdatePrimaryRegion(ctx, in)
		//},
		"Verify": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.VerifyInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.Verify(ctx, in)
		},
		"VerifyMac": func(ctx context.Context, body []byte) (any, []error) {
			var in awskms.VerifyMacInput
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, []error{err}
			}
			return kms.VerifyMac(ctx, in)
		},
	}
}
