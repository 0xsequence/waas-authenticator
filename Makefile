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
	GOBIN=$$PWD/bin \
	go install -v \
		-tags='$(BUILDTAGS)' \
		-gcflags='-e' \
		-trimpath \
		-buildvcs=false \
		-ldflags="-s -w -buildid=" \
		$(1)
endef

build: build-utils build-waas-auth

build-waas-auth:
	$(call build, ./cmd/waas-auth)

build-utils: build-jwt-util

build-jwt-util:
	$(call build, ./cmd/jwt-util)

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
	@docker buildx rm waas-authenticator-buildkit || true
	docker buildx create \
    	--name=waas-authenticator-buildkit \
        --driver=docker-container \
        --driver-opt image=moby/buildkit:v0.12.5@sha256:fc0979ebd6e0a08a5caf9e6807a6c0202d31090b26b56142f3d9217a827a722a \
        --bootstrap \
        --use
	docker buildx build --load .
