# Local KMS (LKMS)

A mock version of AWS' Key Management Service, for local development and testing. Written in Go.

_Whilst this service does use [real encryption](https://golang.org/pkg/crypto/aes/), it is designed for 
development and testing against KMS; not for use in a production environment._

## Features

### Supports

* Symmetric and ECC_NIST keys
* Management of Customer Master Keys; including:
    * Enabling and disabling keys
    * Scheduling key deletion
    * Enabling/disabling automated key rotation
* Management of key aliases
* Encryption
    * Encryption Contexts
* Decryption
* Generating a data key, with or without plain text
* Generating random data
* Signing and verifying messages
    * RAW and DIGEST
* Tags
* Key Policies: Get & Put

#### Seeding
Seeding allows LKMS to be supplied with a set of pre-defined keys and aliases on startup, giving you a deterministic and versionable way to manage test keys.

If a key in the seeding file already exists, it will not be overwritten or amended by the seeding process.

### Does not (yet) support

* RSA or ECC_SECG_P256K1 keys
* Grants
* Importing your own key material
* Operations relating to a Custom Key Store

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

_Currently only Symmetric keys are supported in the seeding file._

A simple seeding file looks like
```yaml
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
        BackingKeys:
          - 5cdaead27fe7da2de47945d73cd6d79e36494e73802f3cd3869f1d2cb0b5d7a9

Aliases:
  - AliasName: alias/testing
    TargetKeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
```
Which will create a single key with the ID `bc436485-5092-42b8-92a3-0aa8b93536dc`, and an alias to the key with the name `alias/testing`.

`BackingKeys ` must be an array of **one or more** hex encoded 256bit keys. Adding more than one backing key simulates the effect of the CMK having been rotated.

Seeding files also support multiple keys, aliases and backing keys.

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
- **NextKeyRotation**: An ISO 8601 formatted date. Supplying this enables key rotation, and sets the next rotation to take place on the supplied date. If the date is in the past, rotation will happen the first time the key is accessed.

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
```

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

Tested with Go 1.12

### Install

```sh
go get -u github.com/nsmithuk/local-kms
cd $GOPATH/src/github.com/nsmithuk/local-kms
dep ensure
go install
```

### Run

```sh
$GOPATH/bin/local-kms

```

Local KMS runs on port http://localhost:8080 by default.

### Using LKMS with the CLI

For a more in-depth guide to theses commands, please see [Using AWS KMS via the CLI](https://nsmith.net/aws-kms-cli).

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
