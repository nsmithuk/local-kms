# syntax=docker/dockerfile:1.7

############################################
# Build stage (Debian-based, not Alpine)
############################################
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

# If your deps include VCS references, git can be needed
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Copy module files first for better caching
COPY go.mod go.sum ./

# Cache Go module downloads
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy the rest of the source
COPY . .

# Build a static binary for the target platform
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" \
    -o /out/local-kms ./...

############################################
# Runtime stage (small, multi-arch)
############################################
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/local-kms /local-kms

ENTRYPOINT ["/local-kms"]
