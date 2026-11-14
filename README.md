# Local KMS (LKMS)

> [!IMPORTANT]
> The `latest` tag on Docker Hub will move to v4 in January 2027. If you rely on v3, update your image reference to `nsmithuk/local-kms:3` before then.

A mock version of AWS' Key Management Service, for local development and testing. Written in Go.

_Whilst this project does use real encryption ([AES](https://pkg.go.dev/crypto/aes), [ECDSA](https://pkg.go.dev/crypto/ecdsa), [RSA](https://pkg.go.dev/crypto/rsa), and [ML-DSA](https://github.com/nsmithuk/ml-dsa)), it is designed for
development and testing against KMS; not for use in a production environment._

## Features

### Supports

* Symmetric (AES) keys
* Asymmetric keys (ECC and RSA)
* Post-quantum keys (ML-DSA: ML_DSA_44, ML_DSA_65, ML_DSA_87)
* HMAC keys (HMAC_224, HMAC_256, HMAC_384, HMAC_512)
* Management of Customer Master Keys; including:
    * Enabling and disabling keys
    * Scheduling key deletion
    * Enabling/disabling automated key rotation
    * On-demand key rotation
* Management of key aliases
* Encryption
    * Encryption Contexts
* Decryption
* Re-encryption
* Generating a data key, with or without plain text
* Generating a data key pair, with or without plain text
* Generating random data
* Importing your own key material
    * Key material expiry (ValidTo / ExpirationModel)
* Signing and verifying messages
    * RAW and DIGEST message types
* Generating and verifying MACs with HMAC keys
* Key Agreement (Derive Shared Secret) for ECC keys
* Tags
* Key Policies: Get & Put

#### Seeding
Seeding allows LKMS to be supplied with a set of pre-defined keys and aliases on startup, giving you a deterministic and versionable way to manage test keys.

If a key in the seeding file already exists, it will not be overwritten or amended by the seeding process.

### Does not support

* Grants
* Operations relating to a Custom Key Store

## Breaking changes from v3

> [!WARNING]
> v4 introduces backwards-incompatible changes with v3.

* **Database format** — v4 uses [PebbleDB](https://github.com/cockroachdb/pebble). Data stored by v3 cannot be read by v4 and must be re-created.
* **Seed file format** — The seed file format has been redesigned (see below). v3 seed files are not compatible with v4. A seed file converter is planned for a future release.

## Download

Pre-built binaries for Linux (amd64, arm64) and macOS (amd64, arm64) are attached to each [GitHub release](https://github.com/nsmithuk/local-kms/releases).


## Getting Started with Docker

Images are available on [Docker Hub](https://hub.docker.com/r/nsmithuk/local-kms).

The quickest way to get started is with Docker. To get LKMS up, running and accessible on port 8080, you can run:
```
docker run -p 8080:8080 nsmithuk/local-kms:4
```

### Seeding and Docker
To use a seed file with Docker, mount a directory containing your `seed.yaml` and set `KMS_SEED_PATH`:
```
docker run -p 8080:8080 \
-e KMS_SEED_PATH=/init/seed.yaml \
--mount type=bind,source="$(pwd)"/init,target=/init \
nsmithuk/local-kms:4
```

### Persisting data and Docker
By default in Docker, data will be stored in the directory `/data/`. To persist data between container executions, mount `/data` to a directory on the host's file system.
```
docker run -p 8080:8080 \
--mount type=bind,source="$(pwd)"/data,target=/data \
nsmithuk/local-kms:4
```

## Seed file format

Seed files must begin with `Version: 2`. Keys are defined as a flat list; each entry has a `KeyId`, a `Metadata` block, and a `Material` block.

A simple seed file looks like:
```yaml
Version: 2

Keys:
  - KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
    Metadata:
      KeySpec: SYMMETRIC_DEFAULT
      KeyUsage: ENCRYPT_DECRYPT
      Description: "My AES key"
    Material:
      BackingKeys:
        - 5cdaead27fe7da2de47945d73cd6d79e36494e73802f3cd3869f1d2cb0b5d7a9

  - KeyId: 01234567-89ab-cdef-0123-456789abcdef
    Metadata:
      KeySpec: HMAC_256
      KeyUsage: GENERATE_VERIFY_MAC
      Description: HMAC key for message authentication
    Material:
      BackingKeys:
        - 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

  - KeyId: 800d5768-3fd7-4edd-a4b8-4c81c3e4c147
    Metadata:
      KeySpec: ECC_NIST_P256
      KeyUsage: SIGN_VERIFY
      Description: ECC key with curve secp256r1
    Material:
      PrivateKeyPem: |
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIMnOrUrXr8rwne7d8f01cfwmpS/w+K7jcyWmmeLDgWKaoAoGCCqGSM49
        AwEHoUQDQgAEYNMBBZ3h1ipuph1iO5k+yLvTs94UN71quXN3f0P/tprs2Fp2FEas
        M7m7XZ2xlDK3wcEAs1QEIoQjjwnhcptQ6A==
        -----END EC PRIVATE KEY-----

Aliases:
  - AliasName: alias/testing
    TargetKeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
```

Which will create three keys and one alias.

`BackingKeys` must be an array of **one or more** hex-encoded keys.
- AES Keys: 256-bit keys (can be generated using `openssl rand -hex 32`)
- HMAC Keys: Key size depends on the KeySpec:
  - HMAC_224: 224-bit keys (28 bytes, `openssl rand -hex 28`)
  - HMAC_256: 256-bit keys (32 bytes, `openssl rand -hex 32`)
  - HMAC_384: 384-bit keys (48 bytes, `openssl rand -hex 48`)
  - HMAC_512: 512-bit keys (64 bytes, `openssl rand -hex 64`)

Only AES and HMAC keys support `BackingKeys`.

Adding more than one backing key simulates the effect of the key having been rotated.

```yaml
Version: 2

Keys:
  - KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
    Metadata:
      KeySpec: SYMMETRIC_DEFAULT
      KeyUsage: ENCRYPT_DECRYPT
    Material:
      BackingKeys:
        - 34743777217A25432A46294A404E635266556A586E3272357538782F413F4428
        - 614E645267556B58703273357638792F423F4528472B4B6250655368566D5971

  - KeyId: 49c5492b-b1bc-42a8-9a5c-b2015e810c1c
    Metadata:
      KeySpec: SYMMETRIC_DEFAULT
      KeyUsage: ENCRYPT_DECRYPT
    Material:
      BackingKeys:
        - 5cdaead27fe7da2de47945d73cd6d79e36494e73802f3cd3869f1d2cb0b5d7a9

Aliases:
  - AliasName: alias/dev
    TargetKeyId: bc436485-5092-42b8-92a3-0aa8b93536dc

  - AliasName: alias/test
    TargetKeyId: 49c5492b-b1bc-42a8-9a5c-b2015e810c1c
```

The `Metadata` block supports the following fields:
- **KeySpec**: The key type. Required.
- **KeyUsage**: The key usage. Required for asymmetric and HMAC keys; defaults to `ENCRYPT_DECRYPT` for symmetric keys.
- **Description**: A free-text description. Optional.

The `NextKeyRotation` field (AES keys only) enables automatic key rotation. Supply an ISO 8601 date for the next rotation. If the date is in the past, rotation occurs on first access.

```yaml
Version: 2

Keys:
  - KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
    Metadata:
      KeySpec: SYMMETRIC_DEFAULT
      KeyUsage: ENCRYPT_DECRYPT
      Description: "Rotating AES key"
    NextKeyRotation: "2025-01-01T00:00:00+00:00"
    Material:
      BackingKeys:
        - 34743777217A25432A46294A404E635266556A586E3272357538782F413F4428
```

Asymmetric keys and ML-DSA keys use `PrivateKeyPem`. Key size / algorithm is determined from the PEM-encoded key. RSA, Ed25519, and ML-DSA keys use PKCS#8 format (`-----BEGIN PRIVATE KEY-----`). ECC keys use SEC1 format (`-----BEGIN EC PRIVATE KEY-----`).

```yaml
Version: 2

Keys:
  - KeyId: ff275b92-0def-4dfc-b0f6-87c96b26c6c7
    Metadata:
      KeySpec: RSA_2048
      KeyUsage: SIGN_VERIFY
      Description: RSA key with 2048 bits
    Material:
      PrivateKeyPem: |
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD21epc1564DeWZ
        ...
        -----END PRIVATE KEY-----

  - KeyId: 800d5768-3fd7-4edd-a4b8-4c81c3e4c147
    Metadata:
      KeySpec: ECC_NIST_P256
      KeyUsage: SIGN_VERIFY
      Description: ECC key with curve secp256r1
    Material:
      PrivateKeyPem: |
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIMnOrUrXr8rwne7d8f01cfwmpS/w+K7jcyWmmeLDgWKaoAoGCCqGSM49
        AwEHoUQDQgAEYNMBBZ3h1ipuph1iO5k+yLvTs94UN71quXN3f0P/tprs2Fp2FEas
        M7m7XZ2xlDK3wcEAs1QEIoQjjwnhcptQ6A==
        -----END EC PRIVATE KEY-----

  - KeyId: d447c3d8-7755-4ab4-935b-59c6dd9d3de2
    Metadata:
      KeySpec: ECC_NIST_EDWARDS25519
      KeyUsage: SIGN_VERIFY
      Description: Ed25519 key
    Material:
      PrivateKeyPem: |
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIFvmi9bcefeQUNL1z8YbE7hCm7avB6yzPYmhKVLKyP6K
        -----END PRIVATE KEY-----

  - KeyId: 636eb3ec-56ca-4248-a38d-47c3ede35441
    Metadata:
      KeySpec: ML_DSA_44
      KeyUsage: SIGN_VERIFY
      Description: ML-DSA-44 post-quantum key
    Material:
      PrivateKeyPem: |
        -----BEGIN PRIVATE KEY-----
        ...
        -----END PRIVATE KEY-----
```

The `PrivateKeyPem` field is a multiline YAML string. Use the `|` block scalar to preserve newlines.

:arrow_right: &nbsp; When choosing signing keys, consider signature size, cost, and compatibility. ECC 256-bit keys produce the smallest signatures. RSA 2048-bit operations are widely supported. ML-DSA keys provide post-quantum security.

## Configuration
The following environment variables can be set to configure LKMS.

- **PORT**: Port on which LKMS will run. Default: `8080`
- **KMS_ACCOUNT_ID**: Dummy AWS account ID to use. Default: `111122223333`
- **KMS_REGION**: Dummy region to use. Default: `eu-west-2`
- **KMS_SEED_PATH**: Path to a YAML seed file. No default — seeding is only performed when this variable is set.
- **KMS_DATA_PATH**: Path LKMS will put its database. Default: `/tmp/local-kms`

> [!WARNING]
> Keys and aliases are stored under their ARN, so their identity includes both `KMS_ACCOUNT_ID` and `KMS_REGION`. Changing these values will make pre-existing data inaccessible.

## Known Differences from AWS' KMS

When successfully calling `ScheduleKeyDeletion`, the timestamp returned from AWS is in Scientific Notation/Standard Form.
For example `1.5565824E9`. The same request to Local KMS will return `1556582400`. This should have no effect on
official AWS SDKs, as from a JSON interpreter's perspective the two are identical. It does however seem difficult to
force Go to return the value in Standard Form.
See: https://github.com/nsmithuk/local-kms/issues/4

## Building from source

### Prerequisites

Requires Go 1.27 or later.

### Install

```sh
git clone https://github.com/nsmithuk/local-kms.git
cd local-kms
go build -o local-kms ./cmd/local-kms
```

### Run

```sh
./local-kms
```

Local KMS runs on port http://localhost:8080 by default.

### Using LKMS with the CLI

The examples here use `awslocal`, which wraps the `aws` command to include the required endpoint.

e.g. The following two commands are equivalent:
```bash
aws kms create-key --endpoint=http://localhost:8080
awslocal kms create-key
```

#### Creating a Customer Master Key
```bash
awslocal kms create-key
```

#### Encrypt data
```bash
awslocal kms encrypt \
--key-id 0579fe9c-129b-490a-adb0-42589ac4a017 \
--plaintext "My Test String"
```

#### Decrypt Data
```bash
awslocal kms decrypt \
--ciphertext-blob fileb://encrypted.dat
```

#### Generate Data Key
```bash
awslocal kms generate-data-key \
--key-id 0579fe9c-129b-490a-adb0-42589ac4a017 \
--key-spec AES_128
```

#### Creating and Using HMAC Keys

Create an HMAC key:
```bash
awslocal kms create-key \
--key-usage GENERATE_VERIFY_MAC \
--key-spec HMAC_256 \
--description "HMAC key for message authentication"
```

Generate a MAC for a message:
```bash
awslocal kms generate-mac \
--key-id 01234567-89ab-cdef-0123-456789abcdef \
--message "$(echo 'Hello, World!' | base64)" \
--mac-algorithm HMAC_SHA_256
```

Verify a MAC:
```bash
awslocal kms verify-mac \
--key-id 01234567-89ab-cdef-0123-456789abcdef \
--message "$(echo 'Hello, World!' | base64)" \
--mac-algorithm HMAC_SHA_256 \
--mac <base64-encoded-mac>
```

#### Importing custom key material
```bash
key_id=${1}
wrappingAlg=${2:-RSAES_OAEP_SHA_256}
expirationModel=${3:-KEY_MATERIAL_DOES_NOT_EXPIRE}
validToInput=${4}

if [ -z "$key_id" ]; then
    echo ""
    echo "Creating new External key"
    key_id=$(awslocal kms create-key --origin EXTERNAL | jq -r '.KeyMetadata.KeyId')
fi

echo ""
echo "Getting Parameters For Import"
importParams=$(awslocal kms get-parameters-for-import \
  --key-id "$key_id" \
  --wrapping-algorithm "$wrappingAlg" \
  --wrapping-key-spec RSA_3072)

pubKeyBinFile=$(mktemp)
echo "$importParams" | jq -r '.PublicKey' | base64 --decode > "$pubKeyBinFile"

importTokenBinFile=$(mktemp)
echo "$importParams" | jq -r '.ImportToken' | base64 --decode > "$importTokenBinFile"

keyMaterial="KeyMaterial-${key_id}.bin"
if [ -f "$keyMaterial" ]; then
    echo ""
    echo "Found existing key material"
else
    echo ""
    echo "Generating key material"
    openssl rand -out "$keyMaterial" 32
fi

echo ""
echo "Encrypting key material using public key"
encryptedKeyMaterial=$(mktemp)
oaepHash="sha$(echo "$wrappingAlg" | grep -o '[0-9]*$')"
openssl pkeyutl \
  -in "$keyMaterial" \
  -out "$encryptedKeyMaterial" \
  -inkey "$pubKeyBinFile" \
  -keyform DER \
  -pubin -encrypt \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:"$oaepHash"

validTo=
if [ -n "$validToInput" ]; then
    validTo="--valid-to $validToInput"
fi

echo ""
echo "Importing key material for key_id $key_id"
awslocal kms import-key-material \
  --key-id "$key_id" \
  --expiration-model "$expirationModel" \
  --import-token fileb://"$importTokenBinFile" \
  --encrypted-key-material fileb://"$encryptedKeyMaterial" \
  $validTo

echo ""
echo "Cleaning up"
rm -f "$pubKeyBinFile" "$importTokenBinFile" "$encryptedKeyMaterial"

echo ""
echo "Describing new state"
awslocal kms describe-key --key-id "$key_id"
```

### Using LKMS with HTTP(ie)

#### Creating a Customer Master Key
```bash
http -v --json POST http://localhost:8080/ \
X-Amz-Target:TrentService.CreateKey
```

#### Encrypting some (base64 encoded) data
```bash
http -v --json POST http://localhost:8080/ \
X-Amz-Target:TrentService.Encrypt \
KeyId=f154ba79-0b7d-4f19-9983-309f706ebc83 \
Plaintext='SGVsbG8='
```

#### Decrypting some KMS cipher text
```bash
http -v --json POST http://localhost:8080/ \
X-Amz-Target:TrentService.Decrypt \
CiphertextBlob='<base64-encoded-ciphertext>'
```

### Generating key material for use in seed files

The following bash functions generate keys in PKCS#8 format ready to paste into a `seed.yaml`. The `uuidgen` and `openssl` packages are required.

#### RSA Key Generation
```bash
function rsakey(){
    local bits=$1
    if ! [[ "$bits" =~ ^(2048|3072|4096)$ ]]; then
        echo "RSA keysize must be one of: 2048 3072 4096"
        return
    fi
    local keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')
    echo "
  - KeyId: ${keyId}
    Metadata:
      KeySpec: RSA_${bits}
      KeyUsage: SIGN_VERIFY  # or ENCRYPT_DECRYPT
      Description: RSA key with ${bits} bits
    Material:
      PrivateKeyPem: |
$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -pkeyopt rsa_keygen_pubexp:65537 | sed 's/^/        /')
"
}
```

```bash
rsakey 2048
rsakey 3072
rsakey 4096
```

#### ECC Key Generation

```bash
function ecckey(){
    local curve=$1
    local usage=${2:-SIGN_VERIFY}
    if ! [[ "$curve" =~ ^(secp256r1|secp384r1|secp521r1|secp256k1)$ ]]; then
        echo "Curve must be one of: secp256r1 secp384r1 secp521r1 secp256k1"
        return
    fi
    declare -A specmap=(
        [secp256r1]=ECC_NIST_P256
        [secp384r1]=ECC_NIST_P384
        [secp521r1]=ECC_NIST_P521
        [secp256k1]=ECC_SECG_P256K1
    )
    local keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')
    echo "
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ${specmap[$curve]}
      KeyUsage: ${usage}
      Description: ECC key with curve ${curve}
    Material:
      PrivateKeyPem: |
$(openssl ecparam -name ${curve} -genkey -noout | sed 's/^/        /')
"
}
```

```bash
ecckey secp256r1
ecckey secp384r1
ecckey secp521r1
ecckey secp256k1
```

For Ed25519 keys:
```bash
function ed25519key(){
    local keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')
    echo "
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ECC_NIST_EDWARDS25519
      KeyUsage: SIGN_VERIFY
      Description: Ed25519 key
    Material:
      PrivateKeyPem: |
$(openssl genpkey -algorithm ed25519 | sed 's/^/        /')
"
}
```

#### HMAC Key Generation

```bash
function hmackey(){
    local keyspec=$1
    if ! [[ "$keyspec" =~ ^(HMAC_224|HMAC_256|HMAC_384|HMAC_512)$ ]]; then
        echo "KeySpec must be one of: HMAC_224 HMAC_256 HMAC_384 HMAC_512"
        return
    fi
    local keysize
    case $keyspec in
        HMAC_224) keysize=28 ;;
        HMAC_256) keysize=32 ;;
        HMAC_384) keysize=48 ;;
        HMAC_512) keysize=64 ;;
    esac
    local keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')
    local backingKey=$(openssl rand -hex "$keysize")
    echo "
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ${keyspec}
      KeyUsage: GENERATE_VERIFY_MAC
      Description: HMAC key for message authentication
    Material:
      BackingKeys:
        - ${backingKey}
"
}
```

```bash
hmackey HMAC_224
hmackey HMAC_256
hmackey HMAC_384
hmackey HMAC_512
```

#### ML-DSA Key Generation

ML-DSA (post-quantum) keys require OpenSSL 3.5 or later. The `scripts/keygen.sh` script included in this repository supports all key types, including ML-DSA:

```bash
./scripts/keygen.sh ML_DSA_44
./scripts/keygen.sh ML_DSA_65
./scripts/keygen.sh ML_DSA_87
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
