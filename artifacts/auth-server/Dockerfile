# stage 1: build
FROM golang:1.12-alpine AS builder
LABEL maintainer="nightfury1204"

# Add source code
RUN mkdir -p /code
ADD . /code

# Build binary
RUN cd /code && \
    GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /go/bin/auth-server

# stage 2: lightweight "release"
FROM alpine:latest
LABEL maintainer="nightfury1204"

COPY --from=builder /go/bin/auth-server /app/

EXPOSE 5001

WORKDIR /app

ENTRYPOINT [ "./auth-server"]
