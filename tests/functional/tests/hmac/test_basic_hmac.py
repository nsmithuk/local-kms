import base64
from pprint import pprint

import pytest


class TestBasicHMAC:
    def test_create_and_use_hmac_key(self, kms_client):
        """Basic test to create HMAC key and perform MAC operations"""

        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey",
            {
                "KeyUsage": "GENERATE_VERIFY_MAC",
                "KeySpec": "HMAC_256",
                "Description": "Test HMAC key",
            },
        )

        assert code == 200
        assert "KeyMetadata" in key_response

        key_metadata = key_response["KeyMetadata"]
        key_id = key_metadata["KeyId"]
        pprint(key_response)

        # Verify key metadata
        assert key_metadata["KeyUsage"] == "GENERATE_VERIFY_MAC"
        assert key_metadata["KeySpec"] == "HMAC_256"
        assert key_metadata["KeyState"] == "Enabled"
        assert "HMAC_SHA_256" in key_metadata["SigningAlgorithms"]

        # Test message
        test_message = "Hello, HMAC World!"
        message_b64 = base64.b64encode(test_message.encode()).decode()

        # Generate MAC
        code, mac_response = kms_client.post(
            "GenerateMac",
            {"KeyId": key_id, "Message": message_b64, "MacAlgorithm": "HMAC_SHA_256"},
        )

        pprint(mac_response)
        assert code == 200
        assert "Mac" in mac_response
        assert "KeyId" in mac_response
        assert "MacAlgorithm" in mac_response
        assert mac_response["MacAlgorithm"] == "HMAC_SHA_256"

        # Verify the MAC is the correct length for SHA-256 (32 bytes)
        mac_bytes = base64.b64decode(mac_response["Mac"])
        assert len(mac_bytes) == 32

        # Verify MAC
        code, verify_response = kms_client.post(
            "VerifyMac",
            {
                "KeyId": key_id,
                "Message": message_b64,
                "Mac": mac_response["Mac"],
                "MacAlgorithm": "HMAC_SHA_256",
            },
        )

        assert code == 200
        assert "MacValid" in verify_response
        assert verify_response["MacValid"] is True
        assert verify_response["MacAlgorithm"] == "HMAC_SHA_256"

        # Verify with wrong message (should fail)
        wrong_message = base64.b64encode("Wrong message".encode()).decode()
        code, verify_wrong_response = kms_client.post(
            "VerifyMac",
            {
                "KeyId": key_id,
                "Message": wrong_message,
                "Mac": mac_response["Mac"],
                "MacAlgorithm": "HMAC_SHA_256",
            },
        )

        assert code == 200
        assert verify_wrong_response["MacValid"] is False

        print(f"✅ HMAC key test passed - Key ID: {key_id}")
