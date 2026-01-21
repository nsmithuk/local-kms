import base64
import json

import pytest


class TestHmacOperations:
    def test_create_hmac_key_256(self, kms_client):
        """Test creating an HMAC_256 key"""
        code, response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )

        assert code == 200
        assert "KeyMetadata" in response
        metadata = response["KeyMetadata"]
        assert metadata["KeyUsage"] == "GENERATE_VERIFY_MAC"
        assert metadata["KeySpec"] == "HMAC_256"
        assert "SigningAlgorithms" in metadata
        assert "HMAC_SHA_256" in metadata["SigningAlgorithms"]

    def test_create_hmac_key_512(self, kms_client):
        """Test creating an HMAC_512 key"""
        code, response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_512"}
        )

        assert code == 200
        assert "KeyMetadata" in response
        metadata = response["KeyMetadata"]
        assert metadata["KeyUsage"] == "GENERATE_VERIFY_MAC"
        assert metadata["KeySpec"] == "HMAC_512"
        assert "HMAC_SHA_512" in metadata["SigningAlgorithms"]

    def test_create_hmac_key_224(self, kms_client):
        """Test creating an HMAC_224 key"""
        code, response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_224"}
        )

        assert code == 200
        assert "KeyMetadata" in response
        metadata = response["KeyMetadata"]
        assert metadata["KeyUsage"] == "GENERATE_VERIFY_MAC"
        assert metadata["KeySpec"] == "HMAC_224"
        assert "HMAC_SHA_224" in metadata["SigningAlgorithms"]

    def test_create_hmac_key_384(self, kms_client):
        """Test creating an HMAC_384 key"""
        code, response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_384"}
        )

        assert code == 200
        assert "KeyMetadata" in response
        metadata = response["KeyMetadata"]
        assert metadata["KeyUsage"] == "GENERATE_VERIFY_MAC"
        assert metadata["KeySpec"] == "HMAC_384"
        assert "HMAC_SHA_384" in metadata["SigningAlgorithms"]

    def test_generate_mac(self, kms_client):
        """Test generating a MAC with HMAC key"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Test message
        message = base64.b64encode(b"Hello, World!").decode("utf-8")

        # Generate MAC
        code, mac_response = kms_client.post(
            "GenerateMac",
            {"KeyId": key_id, "Message": message, "MacAlgorithm": "HMAC_SHA_256"},
        )

        assert code == 200
        assert "Mac" in mac_response
        assert "KeyId" in mac_response
        assert "MacAlgorithm" in mac_response
        assert mac_response["MacAlgorithm"] == "HMAC_SHA_256"
        assert mac_response["KeyId"] == key_response["KeyMetadata"]["Arn"]

        # Decode the MAC to check its length (SHA-256 produces 32 bytes)
        mac_bytes = base64.b64decode(mac_response["Mac"])
        assert len(mac_bytes) == 32

    def test_verify_mac_valid(self, kms_client):
        """Test verifying a valid MAC"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Test message
        message = base64.b64encode(b"Hello, World!").decode("utf-8")

        # Generate MAC
        code, mac_response = kms_client.post(
            "GenerateMac",
            {"KeyId": key_id, "Message": message, "MacAlgorithm": "HMAC_SHA_256"},
        )
        assert code == 200

        # Verify MAC
        code, verify_response = kms_client.post(
            "VerifyMac",
            {
                "KeyId": key_id,
                "Message": message,
                "Mac": mac_response["Mac"],
                "MacAlgorithm": "HMAC_SHA_256",
            },
        )

        assert code == 200
        assert "MacValid" in verify_response
        assert verify_response["MacValid"] is True
        assert verify_response["KeyId"] == key_response["KeyMetadata"]["Arn"]
        assert verify_response["MacAlgorithm"] == "HMAC_SHA_256"

    def test_verify_mac_invalid(self, kms_client):
        """Test verifying an invalid MAC"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Test message
        message = base64.b64encode(b"Hello, World!").decode("utf-8")
        invalid_mac = base64.b64encode(b"invalid_mac_bytes_here_1234567890").decode(
            "utf-8"
        )

        # Verify invalid MAC
        code, verify_response = kms_client.post(
            "VerifyMac",
            {
                "KeyId": key_id,
                "Message": message,
                "Mac": invalid_mac,
                "MacAlgorithm": "HMAC_SHA_256",
            },
        )

        assert code == 200
        assert "MacValid" in verify_response
        assert verify_response["MacValid"] is False

    def test_verify_mac_wrong_message(self, kms_client):
        """Test verifying MAC with wrong message"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Generate MAC for one message
        original_message = base64.b64encode(b"Hello, World!").decode("utf-8")
        code, mac_response = kms_client.post(
            "GenerateMac",
            {
                "KeyId": key_id,
                "Message": original_message,
                "MacAlgorithm": "HMAC_SHA_256",
            },
        )
        assert code == 200

        # Try to verify with different message
        wrong_message = base64.b64encode(b"Hello, Universe!").decode("utf-8")
        code, verify_response = kms_client.post(
            "VerifyMac",
            {
                "KeyId": key_id,
                "Message": wrong_message,
                "Mac": mac_response["Mac"],
                "MacAlgorithm": "HMAC_SHA_256",
            },
        )

        assert code == 200
        assert verify_response["MacValid"] is False

    def test_hmac_512_operations(self, kms_client):
        """Test HMAC_512 operations"""
        # Create HMAC_512 key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_512"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Test message
        message = base64.b64encode(b"Test message for HMAC-512").decode("utf-8")

        # Generate MAC
        code, mac_response = kms_client.post(
            "GenerateMac",
            {"KeyId": key_id, "Message": message, "MacAlgorithm": "HMAC_SHA_512"},
        )

        assert code == 200
        # SHA-512 produces 64 bytes
        mac_bytes = base64.b64decode(mac_response["Mac"])
        assert len(mac_bytes) == 64

        # Verify MAC
        code, verify_response = kms_client.post(
            "VerifyMac",
            {
                "KeyId": key_id,
                "Message": message,
                "Mac": mac_response["Mac"],
                "MacAlgorithm": "HMAC_SHA_512",
            },
        )

        assert code == 200
        assert verify_response["MacValid"] is True

    def test_aes_key_wrong_usage_for_mac(self, kms_client, symmetric_key):
        """Test that AES keys cannot be used for MAC operations"""
        # Try to generate MAC with AES key (should fail)
        message = base64.b64encode(b"test message").decode("utf-8")
        code, response = kms_client.post(
            "GenerateMac",
            {
                "KeyId": symmetric_key["KeyId"],
                "Message": message,
                "MacAlgorithm": "HMAC_SHA_256",
            },
        )

        # Should get a validation error about key usage
        assert code == 400
        assert (
            "ValidationException" in response.get("__type", "")
            or "key usage" in response.get("message", "").lower()
            or "not valid" in response.get("message", "").lower()
        )

    def test_hmac_key_wrong_algorithm(self, kms_client):
        """Test using wrong MAC algorithm for key spec"""
        # Create HMAC_256 key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Try to use HMAC_SHA_512 algorithm (should fail)
        message = base64.b64encode(b"test message").decode("utf-8")
        code, response = kms_client.post(
            "GenerateMac",
            {"KeyId": key_id, "Message": message, "MacAlgorithm": "HMAC_SHA_512"},
        )

        # Should get a validation error about algorithm compatibility
        assert code == 400
        assert (
            "ValidationException" in response.get("__type", "")
            or "not valid" in response.get("message", "").lower()
            or "key spec" in response.get("message", "").lower()
        )

    def test_generate_mac_missing_parameters(self, kms_client):
        """Test error handling for missing parameters"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Missing Message parameter
        code, response = kms_client.post(
            "GenerateMac", {"KeyId": key_id, "MacAlgorithm": "HMAC_SHA_256"}
        )
        assert code == 400

        # Missing MacAlgorithm parameter
        message = base64.b64encode(b"test message").decode("utf-8")
        code, response = kms_client.post(
            "GenerateMac", {"KeyId": key_id, "Message": message}
        )
        assert code == 400

    def test_verify_mac_missing_parameters(self, kms_client):
        """Test error handling for missing parameters in verify MAC"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Missing Mac parameter
        message = base64.b64encode(b"test message").decode("utf-8")
        code, response = kms_client.post(
            "VerifyMac",
            {"KeyId": key_id, "Message": message, "MacAlgorithm": "HMAC_SHA_256"},
        )
        assert code == 400

        # Missing Message parameter
        fake_mac = base64.b64encode(b"fake_mac_12345678901234567890123").decode("utf-8")
        code, response = kms_client.post(
            "VerifyMac",
            {"KeyId": key_id, "Mac": fake_mac, "MacAlgorithm": "HMAC_SHA_256"},
        )
        assert code == 400

    def test_hmac_key_describe(self, kms_client):
        """Test describing HMAC key returns correct metadata"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey",
            {
                "KeyUsage": "GENERATE_VERIFY_MAC",
                "KeySpec": "HMAC_384",
                "Description": "Test HMAC key for authentication",
            },
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Describe the key
        code, describe_response = kms_client.post("DescribeKey", {"KeyId": key_id})
        assert code == 200

        metadata = describe_response["KeyMetadata"]
        assert metadata["KeyUsage"] == "GENERATE_VERIFY_MAC"
        assert metadata["KeySpec"] == "HMAC_384"
        assert metadata["Description"] == "Test HMAC key for authentication"
        assert "HMAC_SHA_384" in metadata["SigningAlgorithms"]
        assert metadata["KeyState"] == "Enabled"

    def test_large_message_mac(self, kms_client):
        """Test MAC generation and verification with large message"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": "HMAC_256"}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Large test message (10KB)
        large_message = base64.b64encode(b"A" * 10240).decode("utf-8")

        # Generate MAC
        code, mac_response = kms_client.post(
            "GenerateMac",
            {"KeyId": key_id, "Message": large_message, "MacAlgorithm": "HMAC_SHA_256"},
        )
        assert code == 200

        # Verify MAC
        code, verify_response = kms_client.post(
            "VerifyMac",
            {
                "KeyId": key_id,
                "Message": large_message,
                "Mac": mac_response["Mac"],
                "MacAlgorithm": "HMAC_SHA_256",
            },
        )

        assert code == 200
        assert verify_response["MacValid"] is True

    @pytest.mark.parametrize(
        "key_spec,algorithm",
        [
            ("HMAC_224", "HMAC_SHA_224"),
            ("HMAC_256", "HMAC_SHA_256"),
            ("HMAC_384", "HMAC_SHA_384"),
            ("HMAC_512", "HMAC_SHA_512"),
        ],
    )
    def test_all_hmac_variants(self, kms_client, key_spec, algorithm):
        """Test all HMAC key specs with their corresponding algorithms"""
        # Create HMAC key
        code, key_response = kms_client.post(
            "CreateKey", {"KeyUsage": "GENERATE_VERIFY_MAC", "KeySpec": key_spec}
        )
        assert code == 200
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Test message
        message = base64.b64encode(f"Test message for {key_spec}".encode()).decode(
            "utf-8"
        )

        # Generate MAC
        code, mac_response = kms_client.post(
            "GenerateMac",
            {"KeyId": key_id, "Message": message, "MacAlgorithm": algorithm},
        )
        assert code == 200

        # Verify MAC
        code, verify_response = kms_client.post(
            "VerifyMac",
            {
                "KeyId": key_id,
                "Message": message,
                "Mac": mac_response["Mac"],
                "MacAlgorithm": algorithm,
            },
        )
        assert code == 200
        assert verify_response["MacValid"] is True

        # Verify expected MAC sizes
        mac_bytes = base64.b64decode(mac_response["Mac"])
        expected_sizes = {
            "HMAC_224": 28,
            "HMAC_256": 32,
            "HMAC_384": 48,
            "HMAC_512": 64,
        }
        assert len(mac_bytes) == expected_sizes[key_spec]
