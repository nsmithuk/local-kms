import pytest
from base64 import b64encode
from pprint import pprint


class TestSigning:

    @pytest.mark.parametrize("key_pair_spec_and_algorithm", [
        ('RSA_2048', 'RSASSA_PSS_SHA_256'),
        ('RSA_3072', 'RSASSA_PSS_SHA_384'),
        ('RSA_4096', 'RSASSA_PSS_SHA_512'),
        ('RSA_2048', 'RSASSA_PKCS1_V1_5_SHA_256'),
        ('RSA_3072', 'RSASSA_PKCS1_V1_5_SHA_384'),
        ('RSA_4096', 'RSASSA_PKCS1_V1_5_SHA_512'),
        ('ECC_NIST_P256', 'ECDSA_SHA_256'),
        ('ECC_NIST_P384', 'ECDSA_SHA_384'),
        ('ECC_NIST_P521', 'ECDSA_SHA_512'),
        ('ECC_SECG_P256K1', 'ECDSA_SHA_256'),
    ])
    def test_message_signing(self, kms_client, key_pair_spec_and_algorithm):

        code, cmk = kms_client.post('CreateKey', {
            "CustomerMasterKeySpec": key_pair_spec_and_algorithm[0],
            "KeyUsage": 'SIGN_VERIFY',
        })
        pprint(cmk)
        assert code == 200

        # -------------------

        message = 'Hello World'

        code, signed = kms_client.post('Sign', {
            'KeyId': cmk['KeyMetadata']['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': key_pair_spec_and_algorithm[1],
            'Message': b64encode(message.encode("utf-8")).decode('ascii')
        })
        pprint(signed)
        assert code == 200
        assert 'Signature' in signed

        # -------------------

        code, verified = kms_client.post('Verify', {
            'KeyId': cmk['KeyMetadata']['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': key_pair_spec_and_algorithm[1],
            'Message': b64encode(message.encode("utf-8")).decode('ascii'),
            'Signature': signed['Signature']
        })
        pprint(verified)
        assert code == 200
        assert 'SignatureValid' in verified
        assert verified['SignatureValid'] is True

        # -------------------

        code, delete = kms_client.post('ScheduleKeyDeletion', {
            'KeyId': cmk['KeyMetadata']['KeyId'],
            'PendingWindowInDays': 7
        })
        pprint(delete)

        assert code == 200
