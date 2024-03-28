CONFIG           ?= $(TOP)/etc/waas-auth.conf
ENV              ?= prod

TOP              := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
OUTDIR           ?= $(TOP)/bin
SHELL            = bash -o pipefail
TEST_FLAGS       ?= -v

define run
	@go run github.com/goware/rerun/cmd/rerun -watch ./ -ignore vendor bin tests data/schema -run \
		'GOGC=off go build -o ./bin/$(1) ./cmd/$(1)/main.go && CONFIG=$(CONFIG) ./bin/$(1)'
endef

run:
	$(call run,waas-auth)

up:
	docker-compose up

define build
	CGO_ENABLED=0 \
	GOARCH=amd64 \
	GOOS=linux \
	go build -v \
		-trimpath \
		-buildvcs=false \
		-ldflags='-s -w -buildid=' \
		-o ./bin/$(1) \
		./cmd/$(1)
endef

build: build-utils build-waas-auth

build-waas-auth:
	$(call build,waas-auth)

build-utils: build-jwt-util

build-jwt-util:
	$(call build,jwt-util)

generate:
	go generate ./...

.PHONY: proto
proto:
	go generate ./proto

clean:
	rm -rf ./bin/*
	rm -rf version.go
	go clean -cache -testcache

test: test-clean
	GOGC=off go test $(TEST_FLAGS) -run=$(TEST) ./...

test-clean:
	GOGC=off go clean -testcache

eif: clean ensure-version
	mkdir -p bin
	docker build --platform linux/amd64 --build-arg VERSION=$(VERSION) --build-arg ENV_ARG=$(ENV) -t waas-authenticator-builder .
	docker run --platform linux/amd64 -v $(OUTDIR):/out waas-authenticator-builder waas-auth.$(VERSION)

ensure-version:
	test -n "$(VERSION)"
	rm -rf version.go
	echo "package waasauthenticator" > version.go
	echo "const VERSION = \"$(VERSION)\"" >> version.go
