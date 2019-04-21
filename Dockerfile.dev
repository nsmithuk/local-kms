FROM golang:1.11-alpine

RUN mkdir -p /go/src/github.com/nsmithuk/local-kms
COPY . /go/src/github.com/nsmithuk/local-kms

WORKDIR /go/src/github.com/nsmithuk/local-kms

RUN apk add --no-cache --update git \
    && go get -u github.com/golang/dep/cmd/dep  \
    && dep ensure   \
    && go get -u github.com/canthefason/go-watcher  \
    && go install github.com/canthefason/go-watcher/cmd/watcher

RUN mkdir /init
RUN mkdir /data

ENV ACCOUNT_ID 111122223333
ENV REGION eu-west-2
ENV DATA_PATH /data

ENV PORT 8080

ENTRYPOINT ["watcher"]
