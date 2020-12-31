from pprint import pprint
from tests import validate_error_response


class TestKeyManagement:

    def test_create_key_failure_key_usage(self, kms_client):
        code, content = kms_client.post('CreateKey', {
            "KeyUsage": "SIGN_VERIFY",
        })

        assert code == 400
        # SIGN_VERIFY is not valid for symmetric keys
        assert validate_error_response(content,
                                       'ValidationException',
                                       'The operation failed because the KeyUsage value of the CMK is SIGN_VERIFY. To perform this operation, the KeyUsage value must be ENCRYPT_DECRYPT.'
                                       )

    def test_create_key_success(self, kms_client):
        payload = {
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Origin": "AWS_KMS",
            "Description": "Test Description",
            "Tags": [
                {
                    "TagKey": "testing-key",
                    "TagValue": "testing-value",
                },
            ]
        }

        code, cmk = kms_client.post('CreateKey', payload)
        pprint(cmk)
        assert code == 200

        assert isinstance(cmk, dict)
        assert 'KeyMetadata' in cmk

        key_metadata = cmk['KeyMetadata']

        assert {'AWSAccountId', 'Arn', 'CreationDate', 'CustomerMasterKeySpec', 'Description', 'Enabled',
                'EncryptionAlgorithms', 'KeyId', 'KeyManager', 'KeyState', 'KeyUsage', 'Origin'}.issubset(
            set(key_metadata.keys()))

        assert payload['CustomerMasterKeySpec'] == key_metadata['CustomerMasterKeySpec']
        assert payload['KeyUsage'] == key_metadata['KeyUsage']
        assert payload['Origin'] == key_metadata['Origin']
        assert payload['Description'] == key_metadata['Description']

        # ---

        code, description = kms_client.post('DescribeKey', {
            "KeyId": key_metadata['Arn']
        })
        pprint(description)
        assert code == 200
        assert cmk == description  # The description should exactly match the original key

        # ---

        code, tags = kms_client.post('ListResourceTags', {
            "KeyId": key_metadata['Arn']
        })
        pprint(tags)
        assert code == 200
        assert isinstance(tags, dict)
        assert tags['Truncated'] is False
        assert payload['Tags'] == tags['Tags']

        # ---

        code, delete = kms_client.post('ScheduleKeyDeletion', {
            'KeyId': cmk['KeyMetadata']['KeyId'],
            'PendingWindowInDays': 7
        })
        pprint(delete)

        assert code == 200
        assert isinstance(delete, dict)
        assert 'DeletionDate' in delete
        assert cmk['KeyMetadata']['Arn'] == delete['KeyId']
