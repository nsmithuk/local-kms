from pprint import pprint
from uuid import uuid4


class TestAliases:
    def test_symmetric_key_alias(self, kms_client, symmetric_key):

        alias_name = f"alias/{str(uuid4())}"

        code, content = kms_client.post(
            'CreateAlias',
            {
                "TargetKeyId": symmetric_key['Arn'],
                "AliasName": alias_name,
            },
        )

        assert code == 200

        # Can we perform some operations with the key, via the alias?

        test_message = 'SGVsbG8gV29ybGQ='

        code, content = kms_client.post(
            'Encrypt',
            {
                "KeyId": alias_name,
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "Plaintext": test_message,
            },
        )

        # Confirm we could encrypt
        assert code == 200

        code, content = kms_client.post(
            'Decrypt',
            {
                "KeyId": alias_name,
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "CiphertextBlob": content['CiphertextBlob'],
            },
        )

        # Confirm we could decrypt
        assert code == 200
        assert content['Plaintext'] == test_message

    def test_rsa_encryption_alias(self, kms_client, rsa_encryption_key):

        alias_name = f"alias/{str(uuid4())}"

        code, content = kms_client.post(
            'CreateAlias',
            {
                "TargetKeyId": rsa_encryption_key['Arn'],
                "AliasName": alias_name,
            },
        )

        assert code == 200

        # Can we perform some operations with the key, via the alias?

        test_message = 'SGVsbG8gV29ybGQ='

        code, content = kms_client.post(
            'Encrypt',
            {
                "KeyId": alias_name,
                "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "Plaintext": test_message,
            },
        )

        # Confirm we could encrypt
        assert code == 200

        code, content = kms_client.post(
            'Decrypt',
            {
                "KeyId": alias_name,
                "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "CiphertextBlob": content['CiphertextBlob'],
            },
        )

        # Confirm we could decrypt
        assert code == 200
        assert content['Plaintext'] == test_message

    def test_rsa_signing_alias(self, kms_client, rsa_signing_key):

        alias_name = f"alias/{str(uuid4())}"

        code, content = kms_client.post(
            'CreateAlias',
            {
                "TargetKeyId": rsa_signing_key['Arn'],
                "AliasName": alias_name,
            },
        )

        assert code == 200

        # Can we perform some operations with the key, via the alias?

        test_message = 'SGVsbG8gV29ybGQ='

        pprint(
            {
                "KeyId": rsa_signing_key['Arn'],
                "Message": test_message,
                "MessageType": "RAW",
                "SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
            }
        )

        code, content = kms_client.post(
            'Sign',
            {
                "KeyId": alias_name,
                "Message": test_message,
                "MessageType": "RAW",
                "SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
            },
        )

        # Confirm we could Sign
        assert code == 200

        code, content = kms_client.post(
            'Verify',
            {
                "KeyId": alias_name,
                "Message": test_message,
                "MessageType": "RAW",
                "SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                "Signature": content['Signature'],
            },
        )

        # Confirm we could Verify
        assert code == 200
