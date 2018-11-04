FROM golang:1.11-alpine

RUN apk update && apk add git

# Install dep
RUN wget -O - https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

RUN mkdir -p /go/src/github.com/nsmithuk/local-kms
COPY . /go/src/github.com/nsmithuk/local-kms

WORKDIR /go/src/github.com/nsmithuk/local-kms

RUN dep ensure

RUN go install

EXPOSE 9090

CMD ["local-kms"]
