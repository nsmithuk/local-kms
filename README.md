# local-kms-go
A local (mock) version of AWS KMS

Currently support just two endpoints:
* encrypt
* decrypt

## Install

```sh
go get -u github.com/NSmithUK/local-kms-go

cd $GOPATH/src/github.com/NSmithUK/local-kms-go

dep ensure

go install

```

## Run

```sh
$GOPATH/bin/local-kms-go

```
