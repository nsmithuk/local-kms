# Local KMS (LKMS)

A mock version of AWS' Key Management Service, for local development and testing. Written in Go.

_Whilst this service does use [real encryption](https://golang.org/pkg/crypto/aes/), it is designed for 
development and testing against KMS; not for use in a production environment._

## Features

### Supports

* Management of Customer Master Keys; including:
    * Enabling and disabling keys
    * Scheduling key deletion
    * Enabling/disabling automated key rotation
* Management of key aliases
* Encryption
* Decryption
* Generating a data key, with or without plain text
* Generating random data

#### Seeding
Seeding allow LKMS to be supplied with a set of pre-defined keys and aliases on startup, giving you a deterministic and versionable way to manage test keys.

If a key in the seeding file already exists, it will not be overwritten or amended by the seeding process.

### Does not (yet) supported

* Tags
* Grants
* Key Policies
* Importing your own key

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

A simple seeding file looks like
```yaml
Keys:
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
- **ACCOUNT_ID**: Dummy AWS account ID to use. Default: 111122223333
- **REGION**: Dummy region to use. Default: eu-west-2
- **SEED_PATH**: Path at which the seeding file is supplied. Default: `/init/seed.yaml`
- **DATA_PATH**: Path LKMS will put its database.
	- Docker default: `/data`
	- Native default: `/tmp/local-kms`

Warning: keys and aliases are stored under their ARN, thus their identity includes both ACCOUNT_ID and REGION. Changing these values will make pre-existing data inaccessible.

## Building from source

### Prerequisites

Tested with Go 1.11

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

### Direct HTTP examples

Creating a Customer Master Key
```console
curl -X "POST" "http://localhost:8080/" \
     -H 'X-Amz-Target: TrentService.CreateKey' \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d $'{}'
```

Encrypting some (base64 encoded) data
```console
curl -X "POST" "http://localhost:8080/" \
     -H 'X-Amz-Target: TrentService.Encrypt' \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d $'{
  "KeyId": "bc436485-5092-42b8-92a3-0aa8b93536dc",
  "Plaintext": "SGVsbG8="
}'
```

Decrypting some KMS cipher text
```console
curl -X "POST" "http://localhost:8080/" \
     -H 'X-Amz-Target: TrentService.Decrypt' \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d $'{
  "KeyId": "bc436485-5092-42b8-92a3-0aa8b93536dc",
  "CiphertextBlob": "S2Fybjphd3M6a21zOmV1LXdlc3QtMjoxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAD39qJkWhnxpBI+ZDosHf3vMcphFfUHYGQ9P9JMzGdLLsYHEWRaw80hxArEdRwt3eI1W6sJcSOjOXLyrvw="
}'
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
