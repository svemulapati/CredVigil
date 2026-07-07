# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src

# git is needed for CredVigil's git-history scanning at build/test time.
RUN apk add --no-cache git

# Cache dependencies first for faster incremental builds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/credvigil ./cmd/credvigil

# ---- Runtime stage ----
FROM alpine:3.20
# git enables `credvigil scan --git`; ca-certificates enables HTTPS clones.
RUN apk add --no-cache git ca-certificates \
    && adduser -D -u 10001 credvigil
COPY --from=build /out/credvigil /usr/local/bin/credvigil
USER credvigil
WORKDIR /repo
ENTRYPOINT ["credvigil"]
CMD ["scan", "."]
