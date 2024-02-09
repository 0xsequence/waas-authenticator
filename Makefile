CONFIG           ?= $(TOP)/etc/waas-auth.conf

TOP              := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
SHELL            = bash -o pipefail
TEST_FLAGS       ?= -v

GITTAG           ?= $(shell git describe --exact-match --tags HEAD 2>/dev/null || :)
GITBRANCH        ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || :)
LONGVERSION      ?= $(shell git describe --tags --long --abbrev=8 --always HEAD)$(echo -$GITBRANCH | tr / - | grep -v '\-master' || :)
VERSION          ?= $(if $(GITTAG),$(GITTAG),$(LONGVERSION))
GITCOMMIT        ?= $(shell git log -1 --date=iso --pretty=format:%H)
GITCOMMITDATE    ?= $(shell git log -1 --date=iso --pretty=format:%cd)
GITCOMMITAUTHOR  ?= $(shell git log -1 --date=iso --pretty="format:%an")


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
		-ldflags="-s -w -buildid=" \
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
	go clean -cache -testcache

test: test-clean
	GOGC=off go test $(TEST_FLAGS) -run=$(TEST) ./...

test-clean:
	GOGC=off go clean -testcache

eif:
	docker build --platform linux/amd64 --build-arg ENV_ARG=next -t waas-authenticator-builder .
	docker run --platform linux/amd64 -v ./bin:/out waas-authenticator-builder
