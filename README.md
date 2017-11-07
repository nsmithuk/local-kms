# local-kms-go
A local (mock) version of AWS KMS

Currently support just two endpoints:
* encrypt
* decrypt

## Setup

```sh
go get -u github.com/NSmithUK/local-kms-go

cd $GOPATH/src/github.com/NSmithUK/local-kms-go

dep ensure

go install

$GOPATH/bin/local-kms-go

```
