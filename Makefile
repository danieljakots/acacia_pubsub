SHELL := /usr/bin/env bash

# The name of the executable (default is current directory name)
TARGET := $(shell echo $${PWD##*/})

# go source files, ignore vendor directory
SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

COMMIT := $(shell git rev-parse --short HEAD)
LDFLAGS=-ldflags "-X=main.COMMIT=$(COMMIT)"

# looks like abuse
.PHONY: all build obsdbuild clean fmt simplify test testcov testcovweb

all: build test

build:
	go build ${LDFLAGS}

obsdbuild:
	GOOS=openbsd GOARCH=amd64 go build ${LDFLAGS} -o ${TARGET}.obsd

clean:
	rm -f ${TARGET}
	rm -f ${TARGET}.obsd
	rm -f coverage.out

fmt:
	gofmt -l -w ${SRC}

simplify:
	gofmt -s -l -w ${SRC}

test:
	go vet
	go test -v

testcov:
	go test -cover -v

testcovweb:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out
	rm -f coverage.out
