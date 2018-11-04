FROM golang:1.11-alpine AS build

RUN apk update && apk add git

RUN mkdir -p /go/src/github.com/nsmithuk/local-kms
COPY . /go/src/github.com/nsmithuk/local-kms

WORKDIR /go/src/github.com/nsmithuk/local-kms

RUN go get -u github.com/golang/dep/cmd/dep
RUN dep ensure && go install



# Build the final container with just the resulting binary
FROM alpine

COPY --from=build /go/bin/local-kms /usr/local/bin/local-kms

CMD ["local-kms"]
