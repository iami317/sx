# Build
FROM golang:1.23.5-alpine AS build-env
RUN apk add --no-cache build-base libpcap-dev
WORKDIR /app
COPY ../../../../Downloads/sx-2.3.4 /app
RUN go mod download
RUN go build ./cmd/sx

# Release
FROM alpine:3.21.2
RUN apk upgrade --no-cache \
    && apk add --no-cache nmap libpcap-dev bind-tools ca-certificates nmap-scripts
COPY --from=build-env /app/sx /usr/local/bin/
ENTRYPOINT ["sx"]