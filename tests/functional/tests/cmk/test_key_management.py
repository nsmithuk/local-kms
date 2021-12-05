from pprint import pprint

import pytest

from tests import validate_error_response


class TestKeyManagement:
    def test_create_key_failure_key_usage(self, kms_client):
        code, content = kms_client.post(
            'CreateKey',
            {
                "KeyUsage": "SIGN_VERIFY",
            },
        )

        assert code == 400
        # SIGN_VERIFY is not valid for symmetric keys
        assert validate_error_response(
            content,
            'ValidationException',
            'The operation failed because the KeyUsage value of the CMK is SIGN_VERIFY. To perform this operation, the KeyUsage value must be ENCRYPT_DECRYPT.',
        )

    def test_create_key_failure_duplicate_spec(self, kms_client):
        code, content = kms_client.post(
            'CreateKey',
            {
                "KeySpec": 'RSA_2048',
                "CustomerMasterKeySpec": 'RSA_2048',
                "KeyUsage": 'ENCRYPT_DECRYPT',
            },
        )

        assert code == 400
        assert validate_error_response(
            content,
            'ValidationException',
            'You cannot specify KeySpec and CustomerMasterKeySpec in the same request. CustomerMasterKeySpec is deprecated.',
        )

    @pytest.mark.parametrize(
        "key_spec_and_usage",
        [
            ('SYMMETRIC_DEFAULT', 'ENCRYPT_DECRYPT'),
            ('RSA_2048', 'ENCRYPT_DECRYPT'),
            ('RSA_3072', 'ENCRYPT_DECRYPT'),
            ('RSA_4096', 'ENCRYPT_DECRYPT'),
            ('RSA_2048', 'SIGN_VERIFY'),
            ('RSA_3072', 'SIGN_VERIFY'),
            ('RSA_4096', 'SIGN_VERIFY'),
            ('ECC_NIST_P256', 'SIGN_VERIFY'),
            ('ECC_NIST_P384', 'SIGN_VERIFY'),
            ('ECC_NIST_P521', 'SIGN_VERIFY'),
            ('ECC_SECG_P256K1', 'SIGN_VERIFY'),
        ],
    )
    def test_create_key_success_keyspec(self, kms_client, key_spec_and_usage):
        payload = {
            "KeySpec": key_spec_and_usage[0],
            "KeyUsage": key_spec_and_usage[1],
            "Origin": "AWS_KMS",
            "Description": "Test Description",
            "Tags": [
                {
                    "TagKey": "key_spec_and_usage",
                    "TagValue": "%s with %s" % key_spec_and_usage,
                },
            ],
        }

        code, cmk = kms_client.post('CreateKey', payload)
        pprint(cmk)
        assert code == 200

        assert isinstance(cmk, dict)
        assert 'KeyMetadata' in cmk

        key_metadata = cmk['KeyMetadata']

        assert {
            'AWSAccountId',
            'Arn',
            'CreationDate',
            'KeySpec',
            'CustomerMasterKeySpec',
            'Description',
            'Enabled',
            'KeyId',
            'KeyManager',
            'KeyState',
            'KeyUsage',
            'Origin',
        }.issubset(set(key_metadata.keys()))

        assert payload['KeySpec'] == key_metadata['KeySpec']
        assert payload['KeySpec'] == key_metadata['CustomerMasterKeySpec']
        assert payload['KeyUsage'] == key_metadata['KeyUsage']
        assert payload['Origin'] == key_metadata['Origin']
        assert payload['Description'] == key_metadata['Description']

        # ---

        code, description = kms_client.post(
            'DescribeKey', {"KeyId": key_metadata['Arn']}
        )
        pprint(description)
        assert code == 200
        assert (
            cmk == description
        )  # The description should exactly match the original key

        # ---

        code, tags = kms_client.post('ListResourceTags', {"KeyId": key_metadata['Arn']})
        pprint(tags)
        assert code == 200
        assert isinstance(tags, dict)
        assert tags['Truncated'] is False
        assert payload['Tags'] == tags['Tags']

        # ---

        code, delete = kms_client.post(
            'ScheduleKeyDeletion',
            {'KeyId': cmk['KeyMetadata']['KeyId'], 'PendingWindowInDays': 7},
        )
        pprint(delete)

        assert code == 200
        assert isinstance(delete, dict)
        assert 'DeletionDate' in delete
        assert cmk['KeyMetadata']['Arn'] == delete['KeyId']

    def test_create_key_success_customermasterkeyspec(self, kms_client):
        """
        Check once using the now deprecated CustomerMasterKeySpec.
        AWS are still supporting this.
        """

        key_spec_and_usage = ('SYMMETRIC_DEFAULT', 'ENCRYPT_DECRYPT')

        payload = {
            "CustomerMasterKeySpec": key_spec_and_usage[0],
            "KeyUsage": key_spec_and_usage[1],
            "Origin": "AWS_KMS",
            "Description": "Test Description",
            "Tags": [
                {
                    "TagKey": "key_spec_and_usage",
                    "TagValue": "%s with %s" % key_spec_and_usage,
                },
            ],
        }

        code, cmk = kms_client.post('CreateKey', payload)
        pprint(cmk)
        assert code == 200

        assert isinstance(cmk, dict)
        assert 'KeyMetadata' in cmk

        key_metadata = cmk['KeyMetadata']

        assert {
            'AWSAccountId',
            'Arn',
            'CreationDate',
            'KeySpec',
            'CustomerMasterKeySpec',
            'Description',
            'Enabled',
            'KeyId',
            'KeyManager',
            'KeyState',
            'KeyUsage',
            'Origin',
        }.issubset(set(key_metadata.keys()))

        assert payload['CustomerMasterKeySpec'] == key_metadata['KeySpec']
        assert payload['CustomerMasterKeySpec'] == key_metadata['CustomerMasterKeySpec']
        assert payload['KeyUsage'] == key_metadata['KeyUsage']
        assert payload['Origin'] == key_metadata['Origin']
        assert payload['Description'] == key_metadata['Description']

        # ---

        code, description = kms_client.post(
            'DescribeKey', {"KeyId": key_metadata['Arn']}
        )
        pprint(description)
        assert code == 200
        assert (
            cmk == description
        )  # The description should exactly match the original key

        # ---

        code, tags = kms_client.post('ListResourceTags', {"KeyId": key_metadata['Arn']})
        pprint(tags)
        assert code == 200
        assert isinstance(tags, dict)
        assert tags['Truncated'] is False
        assert payload['Tags'] == tags['Tags']

        # ---

        code, delete = kms_client.post(
            'ScheduleKeyDeletion',
            {'KeyId': cmk['KeyMetadata']['KeyId'], 'PendingWindowInDays': 7},
        )
        pprint(delete)

        assert code == 200
        assert isinstance(delete, dict)
        assert 'DeletionDate' in delete
        assert cmk['KeyMetadata']['Arn'] == delete['KeyId']
