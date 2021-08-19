import pytest
import unittest
from pprint import pprint
import base64
from Crypto.PublicKey import RSA, ECC

"""
Example Response for generate_key_pair

{'KeyId': 'arn:aws:kms:eu-west-2:111122223333:key/77c995d5-15b3-411e-9943-c5edda7084ec',
 'KeyPairSpec': 'RSA_2048',
 'PrivateKeyCiphertextBlob': 'S2Fybjphd3M6a21zOmV1LXdlc3QtMjoxMTExMjIyMjMzMzM6a2V5Lzc3Yzk5NWQ1LTE1YjMtNDExZS05OTQzLWM1ZWRkYTcwODRlYwAAAAARZWaQpIAvA3Ss/UBL0q8u/pu12BTZnVqFYc8rVQ9bXU/Debt2fccDSqiXMNxJ2HwAnz92JSrLCY5JemsCD7w3uCVG9UPVMFqH8yJTF17kVvCAQW0DgAvnLBuzmXPKNW886l+K00ko5XmOq3tpQZnRrbxqcQT4SDFtTORtutgBJaMCQhyIEvt+nn1h/yzQWt49uDn81WsNaWXP3Agml+S0kU9THlllnwGTGKHQ92UIgAv6kj0e9sxBTA4s8W45f/YYwrqihHgKuKOSknwqZFF9JwUDTeT4CbYD4hklDtrDgp4Y4R5A9drnD1eRtPblsbFaROIjU/vf5QCgOuxZ4h24wybOpuiEyOH3/e/D810zFCY8xoPpe4iSveRUfyMAl8AGtJkY+Y+r6usleBwGsHWqZ0O1bJbms2TZ5ii/gZ9167F8XrMPbg20ShNZ1odD7MA3Jo9GhIxhckMe8Z4T91aZeK9zIjKJyu614BOGAFrvQt91lroGVuSAMfNmxN46C3oZxfRJ53nKCDWSHgW5SxV6WJxKvZnaIT4bBnJB403d8LF3uLdYZqpg7J7xeUOOD/lYwP32c6s0ztmteTJHt5WOORZjTa01MxV4CEg/VT75ho6oDYEZW/xxdRiHmqjc1d6s41UZ+PWH46m+hLDXD0n+LfsFsieTagFCmmVVvfSkjkUTelbzCL/e3XtlMjzsA7TCeqmdkSPdvxhtDVoAT1R6eOwK5xyDxzd+YWUHyV0K5WjsofUlcJBe3aSfcn16otBMQf7UbJNJ70MQ1fiYghbtjmuOHtdaJhSdvBLBI7vrhnhX8gg/Q3HtE8zKmzuIa02/ouXMc/MlP48D9ml0/GkDKnx5aaWX7KeJ8U9wqc66HmZ3zzgHroi8wKbHyd6ye2mN4PcUyDCLuAASnoGRd5ZJAJdX+XpcylwtBSvtdaSo8efWpLT2Jym4YJwImHcjTthHFtBXMRIwiSjfN2IiHyTNgg9NC0YSY2pL6SQkfRAcLaB/URRP19LAXop+rGXYuMuuHGe108H1xOwezcTvHj9KATsPh0hauOyX7o+NY9pcnRwo7/Qej5iAekFNdKlF/y2k7VqJweQGd6IAqaSx5dgD8476B3F+K2KOneJQRRBCggzB0/R2b4oxa0KKYN3e/ouPlyD9aPqH1x5MCeAVcT7TAx/E9rkkUHqi6PNPBJYHaNErZ+tck+2Qe2zyuJZ8oRMizB26267VtP81E2stc/WgESjtkFuHdHPX6uBBz8VdsPQiVVBBUUJsH2UXiMdJ5MDH61aXDmL/X2hOQM26z+ivbNdnsL+nxqi0NPfYK3mLo68nG5/wxeHS3dzfNa76qwzK1HyaNlecQGEBw+2U/41W9T5vUOjz6ssHBUwWyBXebRhEVCIgbLBJSNTdN/CMx4z4XyYzNSp0LJEa5H15Y+DRZjOs/a3m3ffVqZrQbuMJPXD2o/rF0nT8PxcLE97iyEJ68PiuSr/d66qcErmNWBs8tK7sPNwaska8aUbPhmGQHnHtNQhWLbuQtMSAnGcLXZh6CHdEw/aRq/i7ZV3WBLl5arWoHq009ufgQ/jl5vtkM8kqR9n4AfI9w7hV8Lo06fpxm7myTqi9OAaQyWON/NfAinfamSW+a80xsRC43bWucqO1XfiALJMFVNjLL8eD',
 'PrivateKeyPlaintext': 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDA5wU/rggbLRc8M5bMSRIbmK71rWxDBKTpMDxTQ9oVGpX2I+/hX/qdGspuL02CWcrHB+RISltRiNlepFuxwBj6ztS49VTc1BbHB+/YXNYgM+vK+3WaYxjMeC3HJTZ3rYUMvBYXY2qX+XBaEbudGwdvquckBznC9AhOJnK2QVhAMTHfnmjJqZ6/fXaqCJ37xJht6HNir29m/hGedzW7rofdO3Qks/JNLdd8h1nUV5sBumoOE7wmNnfVqoDBmVNtTR+BYKceReTWtF+qGHLpsBqZjeEskT7JPfAFza69tyf/ub8NjCm9d7jyEueoAT4dcs99CnFkBo6s8YDg7W7K8WvZAgMBAAECggEALoeK/JE941A9CohnF1+Ivp9VlG0AcCnunVDFPFBhijWfdn+0nOhJyxtrOKiwSYDfKKL+rXFCFaisxedfNsDfRaAeL379uUZvOBLyB35dJ+deONfuxg6hLLDQWfjf6n4wWaIEsh+I1p+UOiWM25hpcsYGeupDRIMYfcFIai3Y26KWV6l8EEbSDVQ5CdAuzPzlo3F01H2n6DGvsiWj8fIjWL7MCLRcaG8b9ISwWGggI09fZVRTgPqiehNcuZbDTZcw2GXCvLvCGyw4OtRCVrpBKykDffRqtXr41/EcekAN38pTNVeaBcJnQ33Elsd/J0FZOJflTHkUtIz+MfInuuarAQKBgQD287HXDnfLbTBDxK85K/tia5ZZ0jwGui7cPKl16cw1IMsyv+FnxOKX56+pfd4QMHrCM9FSCHtdMk8bjjdGOd72wIpuRceVKHCtplfRNaFN6nZsTBprgNs7cilhq4YghlFdTD2+imPuqTr62dy0tTMIguXDB2yQi1iZPb+IaSIkJwKBgQDH+F04sts+yN87vMdgMYo0cusZd8uQe66xLJmR1awVaPh4NBp9oPtfIk5IOQ7o8q6CuUrSc4a1QAYJyNUlfJabBvLNiLZMMzbxpDKvhG/WcUI7Pd/iJpv+5NdGJnVNb7AbSGLmD2DLObvPc8bm90TzpFwqJS2qei9nIuodnrnv/wKBgQCOttLFx9SvOVC1OUtSLPrALBDdo8OQ17QRDvWX8R9UbLlBgOZQw9V3mCtKNjVJAdtPtAZ58/DnMRXKhOuop/UUgLz/cVAgARjtIb6KZwXrM15ww6JZEkSgHB+SFEAVN8p5sn/UR8HswNwW8CS+QiFV/9+sT/QLrJvtI2Q2/xr97QKBgDb2V8EGv+YQ1fKYX4Bb/W2PDHlSiNvscsZ1yLvhq8uyr2Byiblv7sdmKXgGXse+NCLwBNW1NRhKQZ6c2aDVDpwLm97MLbbh+L8P73J4hzi8poSb7BY/oG69vUGlvmYLRa8qBSzQmz0gYDOT0d6XphcFXOOkllmd/btuSETd5KNHAoGBAJYvFcC+X/I5rVh+DjcDj8lT86R/eYafT0ndGozF+hzEItg8IhTITIGi8+FAH6j5NEX9qsmCsAmZCWIrcVu2/xKAUGCNMWk65Hd20OX8eGd4YL4Uuevc+qVqyNWv2y/kWCpGJhDfN9VrMzFRHGTQHhYRxudvKFP7Nzhei6qeLIcf',
 'PublicKey': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwOcFP64IGy0XPDOWzEkSG5iu9a1sQwSk6TA8U0PaFRqV9iPv4V/6nRrKbi9NglnKxwfkSEpbUYjZXqRbscAY+s7UuPVU3NQWxwfv2FzWIDPryvt1mmMYzHgtxyU2d62FDLwWF2Nql/lwWhG7nRsHb6rnJAc5wvQITiZytkFYQDEx355oyamev312qgid+8SYbehzYq9vZv4Rnnc1u66H3Tt0JLPyTS3XfIdZ1FebAbpqDhO8JjZ31aqAwZlTbU0fgWCnHkXk1rRfqhhy6bAamY3hLJE+yT3wBc2uvbcn/7m/DYwpvXe48hLnqAE+HXLPfQpxZAaOrPGA4O1uyvFr2QIDAQAB'
}
"""

class TestGenerateDataKeyPair:

    @pytest.mark.parametrize("key_pair_spec", [
        'RSA_2048', 'RSA_3072', 'RSA_4096',
        'ECC_NIST_P256', 'ECC_NIST_P384', 'ECC_NIST_P521',
        'ECC_SECG_P256K1'
    ])
    def test_generate_key_pair(self, kms_client, symmetric_key, key_pair_spec):

        code, key_pair = kms_client.post('GenerateDataKeyPair', {
            'KeyId': symmetric_key['KeyId'],
            'KeyPairSpec': key_pair_spec,
            'EncryptionContext': {'test': 'true'},
        })
        pprint(key_pair)

        assert code == 200
        assert isinstance(key_pair, dict)
        assert {'KeyId', 'KeyPairSpec', 'PrivateKeyCiphertextBlob', 'PrivateKeyPlaintext', 'PublicKey'}.issubset(set(key_pair.keys()))
        assert key_pair['KeyId'] == symmetric_key['Arn']
        assert key_pair['KeyPairSpec'] == key_pair_spec

        # ------------------------------------------------------
        # Test Decrypt

        code, decrypted = kms_client.post('Decrypt', {
            'KeyId': symmetric_key['KeyId'],
            'EncryptionContext': {'test': 'true'},
            'CiphertextBlob': key_pair['PrivateKeyCiphertextBlob']
        })
        pprint(decrypted)

        assert code == 200

        # Confirm the decrypted version matches the original supplied plain text version
        assert decrypted['Plaintext'] == key_pair['PrivateKeyPlaintext']

        # ------------------------------------------------------
        # Test Key Public key is derived from Private key

        # Note - LKMS is using PKCS#8 for all private key encoding. I'm struggling to confirm if this is correct.

        private_key_plaintext = base64.b64decode(key_pair['PrivateKeyPlaintext'])

        if key_pair_spec.startswith('RSA'):
            private_key = RSA.import_key(private_key_plaintext)
            public_key = private_key.publickey().export_key(format='DER', pkcs=8)

        elif key_pair_spec.startswith('ECC'):
            private_key = ECC.import_key(private_key_plaintext)
            public_key = private_key.public_key().export_key(format='DER')  # Defaults to PKCS#8

        else:
            raise ValueError('Unknown key type')

        public_key_encoded = str(base64.b64encode(public_key), "utf-8")
        assert public_key_encoded == key_pair['PublicKey']


    @pytest.mark.parametrize("key_pair_spec", [
        'RSA_2048', 'RSA_3072', 'RSA_4096',
        'ECC_NIST_P256', 'ECC_NIST_P384', 'ECC_NIST_P521',
        'ECC_SECG_P256K1'
    ])
    def test_generate_key_pair_without_plaintext(self, kms_client, symmetric_key, key_pair_spec):
        code, key_pair = kms_client.post('GenerateDataKeyPairWithoutPlaintext', {
            'KeyId': symmetric_key['KeyId'],
            'KeyPairSpec': key_pair_spec,
            'EncryptionContext': {'test': 'true'},
        })
        pprint(key_pair)

        assert code == 200
        assert isinstance(key_pair, dict)
        assert {'KeyId', 'KeyPairSpec', 'PrivateKeyCiphertextBlob', 'PublicKey'}.issubset(set(key_pair.keys()))
        assert key_pair['KeyId'] == symmetric_key['Arn']
        assert key_pair['KeyPairSpec'] == key_pair_spec

        assert 'PrivateKeyPlaintext' not in key_pair.keys()  # This is the key thing we're confirming here
