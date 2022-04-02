# Local KMS (LKMS)

A mock version of AWS' Key Management Service, for local development and testing. Written in Go.

_Whilst this project does use real encryption ([AES](https://golang.org/pkg/crypto/aes/), [ECDSA](https://golang.org/pkg/crypto/ecdsa/) and [RSA](https://golang.org/pkg/crypto/rsa/)), it is designed for 
development and testing against KMS; not for use in a production environment._

#### (Local) KMS Usage Guides
* [Using AWS KMS via the CLI with a Symmetric Key](https://nsmith.net/aws-kms-cli)
* [Using AWS KMS via the CLI with Elliptic Curve (ECC) Keys](https://nsmith.net/aws-kms-cli-ecc)
* [Using AWS KMS via the CLI with RSA Keys for Message Signing](https://nsmith.net/aws-kms-cli-rsa-signing)

## Features

### Supports

* Symmetric (AES) keys
* Asymmetric keys (ECC and RSA)
* Management of Customer Master Keys; including:
    * Enabling and disabling keys
    * Scheduling key deletion
    * Enabling/disabling automated key rotation
* Management of key aliases
* Encryption
    * Encryption Contexts
* Decryption
* Generating a data key, with or without plain text
* Generating a data key pair, with or without plain text
* Generating random data
* Importing your own key material
* Signing and verifying messages
    * RAW and DIGEST
* Tags
* Key Policies: Get & Put

#### Seeding
Seeding allows LKMS to be supplied with a set of pre-defined keys and aliases on startup, giving you a deterministic and versionable way to manage test keys.

If a key in the seeding file already exists, it will not be overwritten or amended by the seeding process.

### Does not (yet) support

* Grants
* Operations relating to a Custom Key Store

## Download

Pre-built binaries:
* [local-kms_darwin-amd64.bin](https://local-kms.s3.eu-west-2.amazonaws.com/3/local-kms_darwin-amd64.bin)
* [local-kms_linux-amd64.bin](https://local-kms.s3.eu-west-2.amazonaws.com/3/local-kms_linux-amd64.bin)
* [local-kms_linux-arm64.bin](https://local-kms.s3.eu-west-2.amazonaws.com/3/local-kms_linux-arm64.bin)
* [local-kms_linux-amd64-alpine.bin](https://local-kms.s3.eu-west-2.amazonaws.com/3/local-kms_linux-amd64-alpine.bin)
* [local-kms_linux-arm64-alpine.bin](https://local-kms.s3.eu-west-2.amazonaws.com/3/local-kms_linux-arm64-alpine.bin)


## Getting Started with Docker

The quickest way to get started is with Docker. To get LKMS up, running and accessible on port 8080, you can run:
```
docker run -p 8080:8080 nsmithuk/local-kms
```

### Seeding and Docker
By default LKMS checks for a seeding file within the container at `/init/seed.yaml`. The simplest way of using a seeding file is to mount a directory on the host's file system containing a file named `seed.yaml`.

Then you can run:
```
docker run -p 8080:8080 \
--mount type=bind,source="$(pwd)"/init,target=/init \
nsmithuk/local-kms
```

### Persisting data and Docker
By default in Docker, data will be stored in the directory `/data/`. To persist data between container executions, mount `/data` to a directory on the host's file system.
```
docker run -p 8080:8080 \
--mount type=bind,source="$(pwd)"/data,target=/data \
nsmithuk/local-kms
```

## Seeding file format

_Both Symmetric and Asymmetric (RSA and ECC) keys are supported in the seeding file._

A simple seeding file looks like
```yaml
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
        BackingKeys:
          - 5cdaead27fe7da2de47945d73cd6d79e36494e73802f3cd3869f1d2cb0b5d7a9
  Asymmetric:
    Ecc:
      - Metadata:
          KeyId: 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
          KeyUsage: SIGN_VERIFY
          Description: ECC key with curve secp256k1
        PrivateKeyHex: ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
      - Metadata:
          KeyId: 800d5768-3fd7-4edd-a4b8-4c81c3e4c147
          KeyUsage: SIGN_VERIFY
          Description: ECC key with curve secp256r1
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
Which will create two keys: an AES Key with ID `bc436485-5092-42b8-92a3-0aa8b93536dc` and a 256 bit ECC Key. 
An alias with the name `alias/testing` refers to the AES key.

`BackingKeys ` must be an array of **one or more** hex encoded 256bit keys (can be generated using `openssl rand -hex 32`).
Only AES Keys support backing keys.

Seeding files also support multiple keys, aliases and backing keys. Adding more than one backing key simulates the effect of the CMK having been rotated. 

```yaml
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
        BackingKeys:
          - 34743777217A25432A46294A404E635266556A586E3272357538782F413F4428
          - 614E645267556B58703273357638792F423F4528472B4B6250655368566D5971
      
      - Metadata:
          KeyId: 49c5492b-b1bc-42a8-9a5c-b2015e810c1c
        BackingKeys:
          - 5cdaead27fe7da2de47945d73cd6d79e36494e73802f3cd3869f1d2cb0b5d7a9


Aliases:
  - AliasName: alias/dev
    TargetKeyId: bc436485-5092-42b8-92a3-0aa8b93536dc

  - AliasName: alias/test
    TargetKeyId: 49c5492b-b1bc-42a8-9a5c-b2015e810c1c

```

Keys also support the following optional fields:
- **Metadata -> Description**: A free text field into which you can enter a description of the key.
- **Metadata -> Origin**: Can be set to `EXTERNAL` to seed keys with custom key material. If `Origin` is set to `EXTERNAL` then `BackingKeys` is optional array that can contain at most 1 hex encoded 256bit key.
- **Metadata -> KeyUsage**: For Asymmetric Keys. ECC keys only support SIGN_VERIFY. RSA keys support SIGN_VERIFY or ENCRYPT_DECRYPT.
- **NextKeyRotation**: AES Keys Only. An ISO 8601 formatted date. Supplying this enables key rotation, and sets the next rotation to take place on the supplied date. If the date is in the past, rotation will happen the first time the key is accessed.

```yaml
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
          Description: "Your key description"
        NextKeyRotation: "2019-09-12T15:19:21+00:00"
        BackingKeys:
          - 34743777217A25432A46294A404E635266556A586E3272357538782F413F4428
      - Metadata:
          KeyId: 5ef77041-d1e6-4af1-9a41-e49a4b45efb6
          Origin: EXTERNAL
        BackingKeys:
          - b200b324de29609558e13780160e38fc193f6bec9f9dba58a2be5b37d5098d74
      - Metadata:
          KeyId: 5d05267f-bb87-4d0b-8594-295a4371d414
          Origin: EXTERNAL
```
In the example above, 2 `EXTERNAL` origin keys will be created. 
- a key with the ID `5ef77041-d1e6-4af1-9a41-e49a4b45efb6`, with pre-imported key material 
- a key with the ID `5d05267f-bb87-4d0b-8594-295a4371d414` in a `PendingImport` state


```yaml
Keys:
  Asymmetric:
    Rsa:
      - Metadata:
          KeyId: ff275b92-0def-4dfc-b0f6-87c96b26c6c7
          KeyUsage: SIGN_VERIFY # or ENCRYPT_DECRYPT
          Description: RSA key with 2048 bits
        PrivateKeyPem: |
          -----BEGIN PRIVATE KEY-----
          MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD21epc1564DeWZ
          80XYAXTo4tjqJzEQ6VdpkRfKHraJ4WNqS8N5HjfyzmADVOgqqlbm5M+Qq0/ViMd/
          Xqh+OUNhwvEIo6iZuNbWba3/cUV9ZFpmCv9IWvlNojc3zq0C9/fXeSqXwZWut78d
          AuFodRdAnENiHf9aXv4pIyszAxALCSCd/UCYZRw+XUDPG4pSJrwgz2Ohkqr1SnFF
          1aQt6onjt3Rtfn5IUs7BGEXGd6M3HeIlikSLjdoXEuevVaZO0ysiQdiYDYYQ2eFe
          ytXefRuotRqH4dLpL6beUFRbT1MQVtqC2S0K2wWq8T5gTFejxv6E6eVqRC2xu0lj
          TGDxnUC3AgMBAAECggEAU6K73GV69CZRS86wNbaYpGho0z4gU/ick7qD8wphE2r5
          QoUVYK6qimz+/2H/oKVC+M1Cv2Qsks/buP6b3NkOScvB3AmIET4eHV3gfRMmVoxw
          TO8g/KVGn9V9HD29Rao7ohj+I5mGXEMKUIwvUDOMg2nvMwmzAi35tHqkIo7BGtt8
          gBuuHsZj9PM6MYSSZdrHP52T3K15MaHfrLb97UaryyYnhnUmBA12DBE8MseuYA7w
          JwL3os6MwtLxRxgXnBhkk3Ist83nZNiXESXhN3d98NLS8KbX2wcbnd0B+CqRyvnv
          GbE+CfzxPf/zTsexxpS3TlTR80vAYkubmtWIMG128QKBgQD/iQbZx2xhH6VjYWC6
          +kc03povTKTe/MKUySO7poWjJrGbajrkq7RcXdNCglVSXcKY/BvmgsWRqJc+Jh2z
          enFIcGOuO146FEAr3i4hGjtV01/ukgAl6Ko68gdxjyQLqrJ/bg0qQO57KEhRh5Tb
          mR5mIkG2j2Usr4Llc3LGXIH8VQKBgQD3SNaahwum8+8kXaxgmKwfOL64rM5fLQq3
          f0UGzKZkuRSqXJn9EKuE1rNKX4zNUBWJVF+C4bjRGLz1QRS7j2taqU4awLie+5Ak
          M4Ww8lzHd3uKf+ESCd8DU3TzD+dggtuw+OTqVZdJKA5Kfrbg72ZUyzH3p9Oj/zMu
          QWl3d6TU2wKBgQCaMZs6qoWRjcEE2Ou/p+pz0qcDR6JtE+RuV3kCcJdPPbgKae2j
          sqCg49To2zCVBRK5sdc8H0kMfcjVrbZaaNYWugrMRfKz5Shb0DPRsbyAK45FrT/9
          oAmojAdF1PQRPi17i3LSPmApXMNWvxNp91lKk/1HJfwNHNNFlYZ6f7PICQKBgQCq
          q2ryXCJ+p/11a/F8+eJR6ig37YzBw6SR4RUTDEwLWHIa4q6lKsw2crhrrGbRjWRP
          1BvXiVK1fg1sd+6HRQUjHZb6f+jsUVO6qJSs+5ltUdnCTWBZwtZYxVECMQfQZICc
          NCxKT6iKpUq3v50YwiIug8+IzhwUJB5+3kacXcc14QKBgQDpjYvwAPAq1Rru/Ew4
          hzisDSCY5CLE+X/6dvogWhJBmpaZBKDmUGi6AwK9rcwITZmlR/qU+2WqNdhHxa8S
          uSp1A6OmOHQHA3I+J4veI0kPB2Y0Z65CyfCYm9MsNkcyFYx4tRBSOzAdA+xrJCa4
          y5+KYGmXlaoRhFSq1VO8mGoihA==
          -----END PRIVATE KEY-----
    Ecc:
      - Metadata:
          KeyId: 800d5768-3fd7-4edd-a4b8-4c81c3e4c147
          KeyUsage: SIGN_VERIFY
          Description: ECC key with curve secp256r1
        PrivateKeyPem: |
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEIMnOrUrXr8rwne7d8f01cfwmpS/w+K7jcyWmmeLDgWKaoAoGCCqGSM49
          AwEHoUQDQgAEYNMBBZ3h1ipuph1iO5k+yLvTs94UN71quXN3f0P/tprs2Fp2FEas
          M7m7XZ2xlDK3wcEAs1QEIoQjjwnhcptQ6A==
          -----END EC PRIVATE KEY-----
```
In the example above, 2 asymmetric keys will be created. Both keys may be used for Signing and Verification. Key size
is determined from the PEM encoded key.
 - an RSA key with the ID `ff275b92-0def-4dfc-b0f6-87c96b26c6c7` (2048 bits).
 - an ECC Key with the ID `800d5768-3fd7-4edd-a4b8-4c81c3e4c147` (256 bits).
 
The `PrivateKeyPem` field is a multiline string. In YAML the  pipe character `|` at the end of the line is one way to do this.
PrivateKeyPem is in PKCS8 format and may be generated using Openssl or similar tools.
See below for bash functions to generate the Asymmetric Key format. 

:arrow_right: &nbsp; When choosing signing keys consider signature size but also cost and compatibility.
ECC 256 bit keys provide the smallest signature but RSA 2048 key operations are currently cheaper and are widely used. 

## Configuration
The following environment variables can be set to configure LKMS.

- **PORT**: Port on which LKMS will run. Default: 8080
- **KMS_ACCOUNT_ID**: Dummy AWS account ID to use. Default: 111122223333
- **KMS_REGION**: Dummy region to use. Default: eu-west-2
- **KMS_SEED_PATH**: Path at which the seeding file is supplied. Default: `/init/seed.yaml`
- **KMS_DATA_PATH**: Path LKMS will put its database.
	- Docker default: `/data`
	- Native default: `/tmp/local-kms`

Warning: keys and aliases are stored under their ARN, thus their identity includes both KMS_ACCOUNT_ID and KMS_REGION. Changing these values will make pre-existing data inaccessible.

## Configuration
The following environment variables can be set to configure LKMS.

## Known Differences from AWS' KMS

When successfully calling `ScheduleKeyDeletion`, the timestamp returned from AWS is in Scientific Notation/Standard Form.
For example `1.5565824E9`. The same request to Local KMS will return `1556582400`. This should have no effect on
official AWS SDKs, as from a JSON interpreter's perspective the two are identical. It does however seem difficult to
force Go to return the value in Standard Form.
See: https://github.com/nsmithuk/local-kms/issues/4

## Building from source

### Prerequisites

Tested with Go 1.17

### Install

```sh
go get -u github.com/nsmithuk/local-kms
cd $GOPATH/src/github.com/nsmithuk/local-kms
go install
```

### Run

```sh
$GOPATH/bin/local-kms

```

Local KMS runs on port http://localhost:8080 by default.

### Using LKMS with the CLI

For a more in-depth guide to these commands, please see:
* [Using AWS KMS via the CLI with a Symmetric Key](https://nsmith.net/aws-kms-cli)
* [Using AWS KMS via the CLI with Elliptic Curve (ECC) Keys](https://nsmith.net/aws-kms-cli-ecc)

The examples here use `awslocal`, which wraps the `aws` command to include the required endpoint.

e.g. The following two commands are equivalent
```bash
aws kms create-key --endpoint=http://localhost:4599
and
awslocal kms create-key
```

#### Creating a Customer Master Key
```bash
awslocal kms create-key
```

#### Encrypt data
```bash
awslocal kms Dncrypt \
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

#### Importing custom key material
```bash
key_id=${1}
wrappingAlg=${2:-RSAES_OAEP_SHA_1}
expirationModel=${3:-KEY_MATERIAL_DOES_NOT_EXPIRE}
validToInput=${4}

if [ "$wrappingAlg" == "RSAES_PKCS1_V1_5" ]; then
    echo "RSAES_PKCS1_V1_5 is nto supported by this script. Please use RSAES_OAEP_SHA_[1|256]."
    exit 1
fi

if [ -z "$key_id" ]; then
    echo ""
    echo "Creating new External key"
    key_id=$(awslocal kms create-key --origin EXTERNAL | jq -r '.KeyMetadata.KeyId')
fi

echo ""
echo "Getting Parameters For Import"
importParams=$(awslocal kms get-parameters-for-import --key-id $key_id --wrapping-algorithm $wrappingAlg --wrapping-key-spec RSA_2048)

pubKeyBinFile=$(mktemp)
echo $importParams | jq -r '.PublicKey' | base64 --decode > $pubKeyBinFile

importTokenBinFile=$(mktemp)
echo $importParams | jq -r '.ImportToken' | base64 --decode > $importTokenBinFile

keyMaterial="KeyMaterial-${key_id}.txt"
if [ -f "$keyMaterial" ]; then
  echo ""
  echo "Found existing key material"
else
  echo ""
  echo "Generating key material"
  keyMaterialTmp=$(mktemp)
  openssl rand -out $keyMaterialTmp 32

  # If you want to re-import key material then you'll need to save
  # this file and use it for any subsequent calls to Local KMS
  mv $keyMaterialTmp $keyMaterial
fi

echo ""
echo "Encrypting key material using public key"
encryptedKeyMaterial=$(mktemp)

openssl pkeyutl \
  -in $keyMaterial \
  -out $encryptedKeyMaterial \
  -inkey $pubKeyBinFile \
  -keyform DER \
  -pubin -encrypt \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha$(echo "$wrappingAlg" | sed -r 's/.*_([0-9]+)$/\1/')

validTo=
if [ -n "$validToInput" ]; then
    validTo=" --valid-to $validToInput"
fi

echo ""
echo "Import key material for key_id $key_id"
awslocal kms import-key-material --key-id $key_id \
    --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE \
    --import-token fileb://$importTokenBinFile \
    --encrypted-key-material fileb://$encryptedKeyMaterial \
    $validTo

echo ""
echo "Cleaning up"
rm -f $pubKeyBinFile
rm -f $importTokenBinFile 
rm -f $encryptedKeyMaterial

echo ""
echo "Describing new state"
awslocal kms describe-key --key-id $key_id
```

### Using LKMS with HTTP(ie)

#### Creating a Customer Master Key
```bash
http -v --json POST http://localhost:4599/ \
X-Amz-Target:TrentService.CreateKey

POST / HTTP/1.1
Accept: application/json, */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 0
Content-Type: application/json
Host: localhost:4599
User-Agent: HTTPie/1.0.2
X-Amz-Target: TrentService.CreateKey



HTTP/1.1 200 OK
Content-Length: 329
Content-Type: application/x-amz-json-1.1
Date: Thu, 24 Oct 2019 11:17:30 GMT

{
    "KeyMetadata": {
        "AWSAccountId": "111122223333",
        "Arn": "arn:aws:kms:eu-west-2:111122223333:key/f154ba79-0b7d-4f19-9983-309f706ebc83",
        "CreationDate": 1571915850,
        "Description": "",
        "Enabled": true,
        "KeyId": "f154ba79-0b7d-4f19-9983-309f706ebc83",
        "KeyManager": "CUSTOMER",
        "KeyState": "Enabled",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "Origin": "AWS_KMS"
    }
}
```

#### Encrypting some (base64 encoded) data
```bash
http -v --json POST http://localhost:4599/ \
X-Amz-Target:TrentService.Encrypt \
KeyId=f154ba79-0b7d-4f19-9983-309f706ebc83 \
Plaintext='SGVsbG8='

POST / HTTP/1.1
Accept: application/json, */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 74
Content-Type: application/json
Host: localhost:4599
User-Agent: HTTPie/1.0.2
X-Amz-Target: TrentService.Encrypt

{
    "KeyId": "f154ba79-0b7d-4f19-9983-309f706ebc83",
    "Plaintext": "SGVsbG8="
}

HTTP/1.1 200 OK
Content-Length: 259
Content-Type: application/x-amz-json-1.1
Date: Thu, 24 Oct 2019 11:18:36 GMT

{
    "CiphertextBlob": "S2Fybjphd3M6a21zOmV1LXdlc3QtMjoxMTExMjIyMjMzMzM6a2V5L2YxNTRiYTc5LTBiN2QtNGYxOS05OTgzLTMwOWY3MDZlYmM4MwAAAABjIzzp52djy/L4prvuGoG+jZ6OJzgQGi6n2CRO5dmfJHw=",
    "KeyId": "arn:aws:kms:eu-west-2:111122223333:key/f154ba79-0b7d-4f19-9983-309f706ebc83"
}
```

#### Decrypting some KMS cipher text
```bash
http -v --json POST http://localhost:4599/ \
X-Amz-Target:TrentService.Decrypt \
CiphertextBlob='S2Fybjphd3M6a21zOmV1LXdlc3QtMjoxMTExMjIyMjMzMzM6a2V5L2YxNTRiYTc5LTBiN2QtNGYxOS05OTgzLTMwOWY3MDZlYmM4MwAAAABjIzzp52djy/L4prvuGoG+jZ6OJzgQGi6n2CRO5dmfJHw='

POST / HTTP/1.1
Accept: application/json, */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 174
Content-Type: application/json
Host: localhost:4599
User-Agent: HTTPie/1.0.2
X-Amz-Target: TrentService.Decrypt

{
    "CiphertextBlob": "S2Fybjphd3M6a21zOmV1LXdlc3QtMjoxMTExMjIyMjMzMzM6a2V5L2YxNTRiYTc5LTBiN2QtNGYxOS05OTgzLTMwOWY3MDZlYmM4MwAAAABjIzzp52djy/L4prvuGoG+jZ6OJzgQGi6n2CRO5dmfJHw="
}

HTTP/1.1 200 OK
Content-Length: 110
Content-Type: application/x-amz-json-1.1
Date: Thu, 24 Oct 2019 11:20:17 GMT

{
    "KeyId": "arn:aws:kms:eu-west-2:111122223333:key/f154ba79-0b7d-4f19-9983-309f706ebc83",
    "Plaintext": "SGVsbG8="
}
```
### Generating Asymmetric Keys in seed format
The following shows 2 bash functions for generating keys to use as seeds. The keys are generated in PKCS8 format and 
formatted for use in seed.yaml.

The linux packages `uuidgen` and `openssl` are required.

#### RSA Key Generation
```bash
function rsakey(){
local bits=$1
if ! [[ "$bits" =~ ^(2048|3072|4096)$ ]];
then
   echo "RSA keysize must be one of : 2048 3072 4096"
   return
fi


keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')
echo "
Keys:
  Asymmetric:
    Rsa:
      - Metadata:
          KeyId: ${keyId}
          KeyUsage: SIGN_VERIFY # or ENCRYPT_DECRYPT
          Description: RSA key with ${bits} bits
        PrivateKeyPem: |
$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -pkeyopt rsa_keygen_pubexp:65537 | sed 's/^/          /')
"
}
````
This function can be sourced then executed with the commands below. The output can be pasted into the seed.yaml file.
```bash
rsakey 2048
rsakey 3072
rsakey 4096
```

#### ECC Key Generation 

```bash
function ecckey(){
local curve=$1
if ! [[ "$curve" =~ ^(secp256r1|secp384r1|secp521r1)$ ]];
then
   echo "Curve must be one of: secp256r1 secp384r1 secp521r1"
   return
fi
keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')

echo "
Keys:
  Asymmetric:
    Ecc:
      - Metadata:
          KeyId: ${keyId}
          KeyUsage: SIGN_VERIFY
          Description: ECC key with curve ${curve}
        PrivateKeyPem: |
$(openssl ecparam -name ${curve} -genkey -noout | sed 's/^/          /')
"
}
```

This function can be sourced then executed with the commands below. The output can be pasted into the seed.yaml file.
```bash
ecckey secp256r1
ecckey secp384r1
ecckey secp521r1
```


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
