# Local KMS

A mock version of AWS' Key Management Service, for local development and testing. Written in Go.

_Note - whilst this service does use [real encryption](https://golang.org/pkg/crypto/aes/), it is designed for 
development and testing. Not for use in a production environment._

## Features

### Supports

* Management of Customer Master Keys; including:
    * Scheduling key deletion
    * Enabling automated key rotation
* Management of key Aliases
* Encryption
* Decryption
* Generating a data key, with or without plain text
* Generating random data

### Does not (yet) support

* Grants
* Key Policies
* Tags
* Importing your own key

## Getting Started

### Prerequisites

Requires Go 1.11 or higher.

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

Local KMS runs on port http://localhost:8080

### Examples

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
