import os
import pytest
from KmsClient import KmsClient


@pytest.fixture(scope="session")
def kms_client():
    yield KmsClient(
        aws_access_key=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
        real_kms=False,
        kms_url=os.getenv('KMS_URL', 'http://localhost:4599'),
    )


@pytest.fixture(scope="session")
def symmetric_key(kms_client):
    """
    Create a temporary symmetric key for use in tests that require one.
    The key is marked for deletion once the tests have finished.
    We don't actually test the creation/deletion process here; it's assumed to work.
    :param kms_client:
    :return:
    """
    code, content = kms_client.post('CreateKey')

    yield content['KeyMetadata']

    code, unused = kms_client.post('ScheduleKeyDeletion', {
        'KeyId': content['KeyMetadata']['KeyId'],
        'PendingWindowInDays': 7
    })
    if code != 200:
        raise ValueError('Unable to delete test key %s' % content['KeyMetadata']['KeyId'])
